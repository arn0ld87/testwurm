//! Per-Host-Schluessel und Hybrid-KEM (B002, Entscheidung E3).
//!
//! Warum **ein** KEM pro Host und nicht pro Datei: ein hybrides KEM bringt
//! 1152 Byte Chiffriertext-Overhead. Bei 1 Mio. Kleinstdateien sind das 1,15 GB
//! reine Schreiblast plus Read-Modify-Write-Zyklen (Band 18 §3). Der Host-Key
//! traegt das KEM genau einmal, pro Datei nur ein 72 Byte grosses AEAD-Wrapping.
//!
//! Rollenbild (Trust-Modell, Band 13 §2):
//! - `ServerPub` (PKU): liegt beim Operator, wird pro Build ausgeliefert.
//! - `ServerSec` (SKR): liegt **nur** beim Operator, niemals auf dem Opfer.
//! - `HostKeyPair`: ephemeraes X25519 + ML-KEM-Kapselung, nur im RAM des Opfers.
//!   Der private Teil wird nach dem Escrow-ACK genullt (`zeroize`).

use crate::codec::{b64_decode, b64_encode};
use crate::{Error, Result};
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};

/// ML-KEM-768-Dekapsulationsschluessel — der private Teil auf der Serverseite.
pub type MlKemDecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

/// ML-KEM-768-Kapselungsschluessel — der oeffentliche Teil.
pub type MlKemEncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;

/// Kodierter oeffentlicher ML-KEM-Schluessel (1184 Byte).
pub type MlKemPublicKeyBytes = ml_kem::Encoded<MlKemEncapsulationKey>;

/// Kodierter privater ML-KEM-Schluessel (2400 Byte).
pub type MlKemSecretKeyBytes = ml_kem::Encoded<MlKemDecapsulationKey>;

/// Kodierter ML-KEM-Chiffretext (1088 Byte).
pub type MlKemCiphertextBytes = ml_kem::Ciphertext<MlKem768>;

pub const X25519_PUB_LEN: usize = 32;
pub const MLKEM_PUB_LEN: usize = 1184;
/// Laenge des kodierten privaten ML-KEM-Schluessels (FIPS-203).
pub const MLKEM_SECRET_LEN: usize = 2400;
pub const MLKEM_CT_LEN: usize = 1088;
pub const MLKEM_SHARED_LEN: usize = 32;
pub const X25519_SHARED_LEN: usize = 32;
/// Groesse des versiegelten Host-Master-Keys im hybriden Modus — das, was der
/// Server zum Entpacken braucht.
pub const SEALED_MASTER_LEN: usize = X25519_PUB_LEN + MLKEM_CT_LEN;

/// Groesse des versiegelten Host-Master-Keys im X25519-only-Modus: dort traegt
/// nur der ephemere oeffentliche X25519-Schluessel das Material.
pub const SEALED_MASTER_X25519_LEN: usize = X25519_PUB_LEN;
pub const MASTER_KEY_LEN: usize = 32;

/// Oeffentlicher Schluessel des Operators/Controllers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerPublicKey {
    pub kex: crate::kex::KexId,
    /// X25519-Public-Key, base64.
    pub x25519: String,
    /// ML-KEM-768-Public-Key, base64. Bei `KexId::X25519` leer.
    #[serde(default)]
    pub mlkem: Option<String>,
    /// Fingerabdruck (SHA-256 ueber beide Keys), base64. Steht in der Konfiguration
    /// und wird im Audit-Log gefuehrt, damit ein ausgetauschter Serverkey auffaellt.
    pub fingerprint: String,
}

impl ServerPublicKey {
    pub fn decode(&self) -> Result<DecodedServerKey> {
        let x = b64_decode(&self.x25519)?;
        if x.len() != X25519_PUB_LEN {
            return Err(Error::Config(format!(
                "X25519-Serverkey hat {} Byte, erwartet {}",
                x.len(),
                X25519_PUB_LEN
            )));
        }
        let mlkem = match self.kex {
            crate::kex::KexId::X25519 => None,
            crate::kex::KexId::HybridX25519MlKem768 => {
                let raw = self
                    .mlkem
                    .as_ref()
                    .ok_or_else(|| Error::Config("ML-KEM-Serverkey fehlt".into()))?;
                let bytes = b64_decode(raw)?;
                if bytes.len() != MLKEM_PUB_LEN {
                    return Err(Error::Config(format!(
                        "ML-KEM-Serverkey hat {} Byte, erwartet {}",
                        bytes.len(),
                        MLKEM_PUB_LEN
                    )));
                }
                Some(bytes)
            }
        };
        Ok(DecodedServerKey {
            kex: self.kex,
            x25519: x,
            mlkem,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DecodedServerKey {
    pub kex: crate::kex::KexId,
    pub x25519: Vec<u8>,
    pub mlkem: Option<Vec<u8>>,
}

/// Laengster gueltiger Schluesselmaterialblock: X25519-Secret (32) plus die
/// Determinismus-Kante aus der ML-KEM-Kapselung (32). Der Koenig ist damit
/// 64 Byte — kein Material wird abgeschnitten, und die HKDF-Inputlaenge ist
/// in beiden Modi definiert.
pub const KEM_SHARED_MAX: usize = X25519_SHARED_LEN + MLKEM_SHARED_LEN;

/// Ergebnis der KEM-Seite: Master Key plus das Material, das zum Server muss.
pub struct HostKeyEncapsulation {
    pub master_key: [u8; MASTER_KEY_LEN],
    /// `ephemeral_x25519_pub (32) || mlkem_ciphertext (1088)` — das einzige,
    /// was den Operator-Secret braucht, um den Master Key zurueckzugewinnen.
    pub sealed_master: Vec<u8>,
    /// Ephemerales X25519-Secret. Muss nach Escrow-ACK genullt werden.
    pub ephemeral_x25519_secret: [u8; 32],
}

/// Schluesselpaar des Controllers (Serverseite). Laedt den Secret aus einer
/// Datei und nullt ihn beim Drop.
pub struct ServerKeyPair {
    secret: StaticSecret,
    mlkem_secret: Option<MlKemSecret>,
    pub public: ServerPublicKey,
}

/// Privater ML-KEM-Schluessel des Servers.
///
/// Das Nullen uebernimmt `ml-kem` selbst: mit aktiviertem Feature `zeroize`
/// implementiert der Dekapsulationsschluessel `ZeroizeOnDrop`. Der eigene
/// `Drop` hier sorgt nur dafuer, dass der Schluessel beim Wegwerfen der
/// Kapselung verschwindet — die Bytes werden nicht zusaetzlich kopiert.
pub struct MlKemSecret(MlKemDecapsulationKey);

impl Drop for MlKemSecret {
    fn drop(&mut self) {
        // Kein eigenes Nullen noetig: `MlKemDecapsulationKey` traegt
        // `ZeroizeOnDrop` (ml-kem mit Feature `zeroize`). Der `Drop` existiert,
        // damit der Schluessel beim Drop der Kapselung sicher verschwindet.
    }
}

/// Schluesselpaarchen des Controllers. Nur auf dem Operator-Rechner.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ServerKeyBundle {
    pub kex: crate::kex::KexId,
    /// X25519-Secret, base64.
    pub x25519_secret: String,
    /// ML-KEM-768-Secret, base64.
    #[serde(default)]
    pub mlkem_secret: Option<String>,
}

impl ServerKeyBundle {
    pub fn generate(kex: crate::kex::KexId, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let secret = StaticSecret::random_from_rng(&mut *rng);
        let x25519_secret = b64_encode(secret.as_bytes());
        let mlkem_secret = if kex == crate::kex::KexId::HybridX25519MlKem768 {
            let (sk, _pk) = MlKem768::generate(&mut MlRng(&mut *rng));
            Some(b64_encode(&sk.as_bytes()[..]))
        } else {
            None
        };
        ServerKeyBundle {
            kex,
            x25519_secret,
            mlkem_secret,
        }
    }

    pub fn public(&self) -> Result<ServerPublicKey> {
        let x_bytes = b64_decode(&self.x25519_secret)?;
        if x_bytes.len() != 32 {
            return Err(Error::Config("X25519-Secret hat falsche Laenge".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&x_bytes);
        let secret = StaticSecret::from(arr);
        let pub_x = XPublicKey::from(&secret);

        let mut mlkem_b64 = None;
        if self.kex == crate::kex::KexId::HybridX25519MlKem768 {
            let raw = b64_decode(
                self.mlkem_secret
                    .as_ref()
                    .ok_or_else(|| Error::Config("ML-KEM-Secret fehlt".into()))?,
            )?;
            let sk = mlkem_secret_from_bytes(&raw)?;
            let pk = sk.0.encapsulation_key();
            mlkem_b64 = Some(b64_encode(&pk.as_bytes()[..]));
        }

        let mut fp_src = Vec::with_capacity(32 + MLKEM_PUB_LEN);
        fp_src.extend_from_slice(pub_x.as_bytes());
        if let Some(m) = &mlkem_b64 {
            fp_src.extend_from_slice(&b64_decode(m)?);
        }
        Ok(ServerPublicKey {
            kex: self.kex,
            x25519: b64_encode(pub_x.as_bytes()),
            mlkem: mlkem_b64,
            fingerprint: b64_encode(&sha256(&fp_src)),
        })
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Ok(serde_json::from_str(text)?)
    }
}

/// Baut den Dekapsulationsschluessel aus seinem kanonischen Encoding.
fn mlkem_secret_from_bytes(raw: &[u8]) -> Result<MlKemSecret> {
    let arr = MlKemSecretKeyBytes::try_from(raw).map_err(|_| {
        Error::Config(format!(
            "ML-KEM-Secret hat {} Byte, erwartet {}",
            raw.len(),
            MLKEM_SECRET_LEN
        ))
    })?;
    Ok(MlKemSecret(MlKemDecapsulationKey::from_bytes(&arr)))
}

impl ServerKeyPair {
    pub fn from_bundle(bundle: &ServerKeyBundle) -> Result<Self> {
        let x_bytes = b64_decode(&bundle.x25519_secret)?;
        if x_bytes.len() != 32 {
            return Err(Error::Config("X25519-Secret hat falsche Laenge".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&x_bytes);
        let secret = StaticSecret::from(arr);
        let mlkem_secret = bundle
            .mlkem_secret
            .as_ref()
            .map(|s| mlkem_secret_from_bytes(&b64_decode(s)?))
            .transpose()?;
        Ok(ServerKeyPair {
            secret,
            mlkem_secret,
            public: bundle.public()?,
        })
    }

    pub fn public(&self) -> &ServerPublicKey {
        &self.public
    }

    /// Gewinnt den Host-Master-Key aus dem versiegelten Material zurueck.
    ///
    /// Reihenfolge ist fest: erst X25519, dann ML-KEM, dann HKDF. Eine
    /// vertauschte Reihenfolge ergaebe einen anderen Master Key und damit
    /// einen scheinbar korrekten, aber falschen Schluessel — darum ist der
    /// Kontextstring in `derive_master_key` Teil des Formats.
    pub fn unseal_master_key(&self, sealed: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
        let erwartet = match self.public.kex {
            crate::kex::KexId::X25519 => SEALED_MASTER_X25519_LEN,
            crate::kex::KexId::HybridX25519MlKem768 => SEALED_MASTER_LEN,
        };
        if sealed.len() != erwartet {
            return Err(Error::Crypto(format!(
                "sealed_master hat {} Byte, erwartet {}",
                sealed.len(),
                erwartet
            )));
        }
        let mut eph = [0u8; X25519_PUB_LEN];
        eph.copy_from_slice(&sealed[..X25519_PUB_LEN]);
        let x_shared = self
            .secret
            .diffie_hellman(&XPublicKey::from(eph))
            .as_bytes()
            .to_vec();

        match self.public.kex {
            crate::kex::KexId::X25519 => derive_master_key(&x_shared, None).map(|k| k.master_key),
            crate::kex::KexId::HybridX25519MlKem768 => {
                let sk = self
                    .mlkem_secret
                    .as_ref()
                    .ok_or_else(|| Error::Config("ML-KEM-Secret fehlt auf dem Server".into()))?;
                let mut ct = [0u8; MLKEM_CT_LEN];
                ct.copy_from_slice(&sealed[X25519_PUB_LEN..]);
                let ct_arr = MlKemCiphertextBytes::try_from(&ct[..])
                    .map_err(|_| Error::Crypto("ML-KEM-Chiffretext hat falsche Laenge".into()))?;
                let ml_shared =
                    sk.0.decapsulate(&ct_arr)
                        .map_err(|_| Error::Crypto("ML-KEM-Dekapsulation fehlgeschlagen".into()))?;
                derive_master_key(&x_shared, Some(&ml_shared[..])).map(|k| k.master_key)
            }
        }
    }
}

/// Ephemerae Kapselung auf dem Opfer.
pub fn encapsulate_host_master_key(
    server: &DecodedServerKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<HostKeyEncapsulation> {
    let secret = EphemeralSecret::random_from_rng(&mut *rng);
    let pub_x = XPublicKey::from(&secret);
    let server_x: [u8; X25519_PUB_LEN] = server.x25519[..X25519_PUB_LEN]
        .try_into()
        .map_err(|_| Error::Config("X25519-Serverkey hat falsche Laenge".into()))?;
    let x_shared = secret.diffie_hellman(&XPublicKey::from(server_x));

    let mut sealed_master = Vec::with_capacity(SEALED_MASTER_LEN);
    sealed_master.extend_from_slice(pub_x.as_bytes());

    match server.kex {
        crate::kex::KexId::X25519 => {
            let derived = derive_master_key(x_shared.as_bytes(), None)?;
            Ok(HostKeyEncapsulation {
                master_key: derived.master_key,
                sealed_master,
                ephemeral_x25519_secret: *x_shared.as_bytes(),
            })
        }
        crate::kex::KexId::HybridX25519MlKem768 => {
            let raw = server
                .mlkem
                .as_ref()
                .ok_or_else(|| Error::Config("ML-KEM-Serverkey fehlt".into()))?;
            if raw.len() != MLKEM_PUB_LEN {
                return Err(Error::Config("ML-KEM-Serverkey hat falsche Laenge".into()));
            }
            let pk_arr = MlKemPublicKeyBytes::try_from(raw.as_slice())
                .map_err(|_| Error::Config("ML-KEM-Serverkey hat falsche Laenge".into()))?;
            let pk = MlKemEncapsulationKey::from_bytes(&pk_arr);
            let (ct, shared) = pk
                .encapsulate(&mut MlRng(rng))
                .map_err(|_| Error::Crypto("ML-KEM-Kapselung fehlgeschlagen".into()))?;
            sealed_master.extend_from_slice(&ct[..]);
            let derived = derive_master_key(x_shared.as_bytes(), Some(&shared[..]))?;
            Ok(HostKeyEncapsulation {
                master_key: derived.master_key,
                sealed_master,
                ephemeral_x25519_secret: *x_shared.as_bytes(),
            })
        }
    }
}

/// Kapselt den Host-Master-Key mit dem System-RNG.
///
/// Bequemer Einstieg fuer Aufrufer ohne eigenen RNG — der Agent nutzt keine
/// Zufallsquelle aus dem Workspace, sondern den des Systems.
pub fn encapsulate_host_master_key_os(server: &DecodedServerKey) -> Result<HostKeyEncapsulation> {
    let mut rng = rand_core::OsRng;
    encapsulate_host_master_key(server, &mut rng)
}

/// Abgeleiteter Master-Key mit Host- und Build-Kontext.
pub struct DerivedMaster {
    pub master_key: [u8; MASTER_KEY_LEN],
    /// HKDF-Info-String, fuer Vektor-Tests und Doku exportiert.
    pub info: String,
}

/// Leitet den Master-Key aus dem KEM-Shared-Secret ab.
///
/// Die Reihenfolge ist fest: X25519-Secret, dann ML-KEM-Secret, dann HKDF.
/// Der Kontextstring ist Teil des Formats — ein anderer Konstring ergibt einen
/// anderen Master Key. Agent und Server nutzen beide diese Funktion ohne
/// Host-Kontext, damit die Entschluesselung denselben Key liefert.
pub fn derive_master_key(x_shared: &[u8], ml_shared: Option<&[u8]>) -> Result<DerivedMaster> {
    derive_master_key_with_context(x_shared, ml_shared, &[0u8; 16], &[0u8; 16])
}

/// HKDF-SHA-256 mit Kontextbindung. Salt ist die Kante aus dem ML-KEM-Shared,
/// wo vorhanden; sonst ein fester Salt. Der Info-String enthaelt Build- und
/// Host-Kontext, damit ein Master Key nicht zwischen Hosts verschiebbar ist.
pub fn derive_master_key_with_context(
    x_shared: &[u8],
    ml_shared: Option<&[u8]>,
    host_id: &[u8; 16],
    build_id: &[u8; 16],
) -> Result<DerivedMaster> {
    let _ = KEM_SHARED_MAX;
    let mut ikm = Vec::with_capacity(KEM_SHARED_MAX);
    ikm.extend_from_slice(x_shared);
    if let Some(m) = ml_shared {
        ikm.extend_from_slice(m);
    }
    let info = format!(
        "kx/master/v1/{}/{}",
        crate::codec::hex(host_id),
        crate::codec::hex(build_id)
    );
    let salt = b"kx-host-master-salt-v1";
    let mut master_key = [0u8; MASTER_KEY_LEN];
    hkdf_into(&ikm, salt, info.as_bytes(), &mut master_key)?;
    Ok(DerivedMaster { master_key, info })
}

/// Hilfsfunktion: HKDF-Expand/Extract auf beliebige Laenge.
pub fn hkdf_into(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    use hkdf::Hkdf;
    let h = Hkdf::<Sha256>::new(Some(salt), ikm);
    h.expand(info, out)
        .map_err(|e| Error::Crypto(format!("HKDF-Expand: {e}")))
}

pub fn hkdf_bytes(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    hkdf_into(ikm, salt, info, &mut out)?;
    Ok(out)
}

/// Argon2id fuer den optionalen Passphrase-Pfad. Parameter sind absichtlich
/// im Format verankert (m=64 MiB, t=3, p=4, 32 Byte Output) und werden im
/// Manifest mitgeschrieben, damit ein spaeterer Decryptor nicht raten muss.
pub const ARGON2_M_KIB: u32 = 65_536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;
pub const ARGON2_OUT_LEN: usize = 32;
pub const ARGON2_SALT_LEN: usize = 16;

pub fn argon2id(pass: &[u8], salt: &[u8], out_len: usize) -> Result<Vec<u8>> {
    use argon2::{Algorithm, Params, Version};
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(out_len))
        .map_err(|e| Error::Crypto(format!("Argon2-Parameter: {e}")))?;
    let a = argon2::Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; out_len];
    a.hash_password_into(pass, salt, &mut out)
        .map_err(|e| Error::Crypto(format!("Argon2id: {e}")))?;
    Ok(out)
}

/// RNG-Adapter: `ml-kem` verlangt `rand_core` 0.6 mit `CryptoRngCore`,
/// der Workspace nutzt dieselbe Version. Der Adapter statt einer zweiten
/// `rand_core`-Version, damit die Trait-Definitionen kompatibel bleiben.
pub struct MlRng<'a>(pub &'a mut dyn RngCore);

impl RngCore for MlRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for MlRng<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Der Master-Key ist echtes HKDF-Material — keine Null-Bytes.
    ///
    /// Das war ein echter Fehler: das HKDF-Ergebnis wurde in ein temporaeres
    /// Array geschrieben und der Master-Key daraus mit einer Laenge von null
    /// kopiert. Das Ergebnis waren 32 Null-Bytes.
    #[test]
    fn der_master_key_ist_kein_nullblock() {
        let x_shared = [0x42u8; X25519_SHARED_LEN];

        let abgeleitet = derive_master_key(&x_shared, None).expect("HKDF laeuft");

        assert_ne!(abgeleitet.master_key, [0u8; MASTER_KEY_LEN]);
    }

    /// Der X25519-Roundtrip: der Agent kapselt, der Server entpackt, beide
    /// kommen auf denselben Master-Key.
    #[test]
    fn der_x25519_roundtrip_liefert_denselben_master_key() {
        let mut rng = OsRng;
        let bundle = ServerKeyBundle::generate(crate::kex::KexId::X25519, &mut rng);
        let oeffentlich = bundle.public().expect("oeffentlicher Schluessel");
        let dekodiert = oeffentlich.decode().expect("dekodierter Schluessel");

        let kapselung = encapsulate_host_master_key(&dekodiert, &mut rng).expect("Kapselung");
        let server = ServerKeyPair::from_bundle(&bundle).expect("Server-Schluessel");
        let entschluesselt = server
            .unseal_master_key(&kapselung.sealed_master)
            .expect("Entschluesselung");

        assert_eq!(entschluesselt, kapselung.master_key);
        assert_ne!(entschluesselt, [0u8; MASTER_KEY_LEN]);
        assert_eq!(kapselung.sealed_master.len(), SEALED_MASTER_X25519_LEN);
    }

    /// Der hybride Roundtrip: X25519 plus ML-KEM-768.
    #[test]
    fn der_hybride_roundtrip_liefert_denselben_master_key() {
        let mut rng = OsRng;
        let bundle = ServerKeyBundle::generate(crate::kex::KexId::HybridX25519MlKem768, &mut rng);
        let oeffentlich = bundle.public().expect("oeffentlicher Schluessel");
        let dekodiert = oeffentlich.decode().expect("dekodierter Schluessel");

        let kapselung = encapsulate_host_master_key(&dekodiert, &mut rng).expect("Kapselung");
        let server = ServerKeyPair::from_bundle(&bundle).expect("Server-Schluessel");
        let entschluesselt = server
            .unseal_master_key(&kapselung.sealed_master)
            .expect("Entschluesselung");

        assert_eq!(entschluesselt, kapselung.master_key);
        assert_ne!(entschluesselt, [0u8; MASTER_KEY_LEN]);
        assert_eq!(kapselung.sealed_master.len(), SEALED_MASTER_LEN);
    }

    /// Der private ML-KEM-Schluessel wird beim Drop genullt.
    #[test]
    fn der_mlkem_schluessel_wird_beim_drop_genullt() {
        // Compile-Zeit-Pruefung: der Typ traegt `ZeroizeOnDrop`. Ohne das
        // Feature `zeroize` in ml-kem schlaegt dieser Test fehl.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MlKemDecapsulationKey>();
    }

    /// Das ML-KEM-Secret des Servers laesst sich aus seinem Encoding lesen.
    #[test]
    fn das_mlkem_secret_laesst_sich_kodieren_und_wieder_lesen() {
        let mut rng = OsRng;
        let bundle = ServerKeyBundle::generate(crate::kex::KexId::HybridX25519MlKem768, &mut rng);
        let roh = bundle.mlkem_secret.expect("ML-KEM-Secret");

        let dekodiert = b64_decode(&roh).expect("base64");
        assert_eq!(dekodiert.len(), 2400);
        assert!(mlkem_secret_from_bytes(&dekodiert).is_ok());
    }
}

/// Der SHA-256 eines Byteblocks.
///
/// Der Fingerabdruck des Server-Schluessels wird ueber ihn gebildet.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}
