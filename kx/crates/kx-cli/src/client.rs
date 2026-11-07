//! HTTP-Client für die kx-server-API mit TLS und Bearer-Auth.

use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ureq::Agent;

/// Fehler bei API-Requests.
#[derive(Debug, Error)]
pub enum ApiError {
    /// TLS-Setup fehlgeschlagen.
    #[error("TLS-Setup fehlgeschlagen: {0}")]
    Tls(String),
    /// HTTP-Request fehlgeschlagen.
    #[error("HTTP-Request fehlgeschlagen: {0}")]
    Http(String),
    /// Antwort-JSON ungültig.
    #[error("Antwort-JSON ungültig: {0}")]
    Json(String),
    /// Datei-I/O-Fehler.
    #[error("Datei-I/O-Fehler: {0}")]
    Io(String),
}

/// Registrierter Host (entspricht dem Server-JSON).
#[derive(Debug, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Erbeutetes Secret (entspricht dem Server-JSON).
#[derive(Debug, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub host_id: String,
    pub cred_type: String,
    pub username: String,
    pub password: String,
    pub source: String,
    pub collected_at: String,
}

/// Task (entspricht dem Server-JSON).
#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub host_id: String,
    pub command: String,
    pub status: String,
    pub output: Option<String>,
    pub created_at: String,
}

/// API-Client mit ureq-Agent und Auth-Token.
pub struct Client {
    agent: Agent,
    base_url: String,
    token: String,
}

impl Client {
    /// Erzeugt einen Client für den angegebenen Server.
    pub fn new(server: &str, token: &str, cert: &str) -> Result<Self, ApiError> {
        let cert_pem = std::fs::read(cert)
            .map_err(|e| ApiError::Tls(format!("Zertifikat nicht lesbar: {e}")))?;
        let client_config = kx_tls::client_config_trusting(&cert_pem)
            .map_err(|e| ApiError::Tls(e.to_string()))?;
        let agent = ureq::AgentBuilder::new().tls_config(client_config).build();
        Ok(Self {
            agent,
            base_url: server.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Liefert alle Hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>, ApiError> {
        get_json(&self.agent, &format!("{}/api/hosts", self.base_url), &self.token)
    }

    /// Liefert alle Secrets.
    pub async fn secrets(&self) -> Result<Vec<Secret>, ApiError> {
        get_json(&self.agent, &format!("{}/api/secrets", self.base_url), &self.token)
    }

    /// Liefert alle Tasks.
    pub async fn tasks(&self) -> Result<Vec<Task>, ApiError> {
        get_json(&self.agent, &format!("{}/api/tasks", self.base_url), &self.token)
    }
}

/// Führt einen GET-Request durch und parst die JSON-Antwort.
fn get_json<T: for<'de> Deserialize<'de>>(
    agent: &Agent,
    url: &str,
    token: &str,
) -> Result<T, ApiError> {
    let resp = agent
        .get(url)
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| ApiError::Http(e.to_string()))?;
    let body = resp
        .into_string()
        .map_err(|e| ApiError::Http(e.to_string()))?;
    serde_json::from_str(&body).map_err(|e| ApiError::Json(e.to_string()))
}

/// Exportiert Secrets als JSON oder CSV.
pub fn export(secrets: &[Secret], path: &Path, format: &str) -> Result<(), ApiError> {
    let mut file = std::fs::File::create(path).map_err(|e| ApiError::Io(e.to_string()))?;
    match format {
        "csv" => {
            writeln!(file, "host_id,cred_type,username,password,source,collected_at")
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
        let secrets = vec![Secret {
            id: "1".into(),
            host_id: "h1".into(),
            cred_type: "password".into(),
            username: "admin".into(),
            password: "secret".into(),
            source: "test".into(),
            collected_at: "2025-11-07T00:00:00Z".into(),
        }];
        let dir = std::env::temp_dir();
        let path = dir.join("kx-cli-test.csv");
        export(&secrets, &path, "csv").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("admin"));
        std::fs::remove_file(path).ok();
    }
}
