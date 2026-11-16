//! Die Fehlertaxonomie des Kerns.
//!
//! Der Kern hat **eine** Fehlerart: `Error`. Sie unterscheidet, was schiefging
//! — ein Formatfehler, ein Kryptografiefehler, eine Fehlkonfiguration, ein
//! inkonsistenter Zustand.
//!
//! Vorher stand hier ein Katalog: eine Fehlerklasse (`ErrorClass`), eine
//! errno-Tabelle, eine Win32-Tabelle und Konstruktoren für Dateifehler. Keine
//! davon hatte einen Aufrufer außerhalb dieses Moduls — die errno- und die
//! Win32-Tabelle erreichte kein einziger Test, und die Win32-Tabelle wurde
//! nicht einmal übersetzt.
//!
//! **Was nicht hier steht, wird auch nicht behauptet.** Die Fehler der
//! anderen Crates haben ihre eigenen Typen (`ExploitError`, `TransportError`,
//! `ApiError`) — ein gemeinsames Enum über die Crates hinweg wurde am
//! 2026-11-15 ausdrücklich abgelehnt.

use thiserror::Error;

/// Ein Fehler im Kern.
#[derive(Debug, Error)]
pub enum Error {
    /// Das Format einer Struktur ist falsch.
    #[error("Formatfehler: {0}")]
    Format(String),
    /// Die Kryptografie hat versagt.
    #[error("Kryptografiefehler: {0}")]
    Crypto(String),
    /// Die Konfiguration ist unvollständig oder widersprüchlich.
    #[error("Fehlkonfiguration: {0}")]
    Config(String),
    /// Ein inkonsistenter Zustand.
    #[error("Zustandsfehler: {0}")]
    State(String),
    /// Die Serialisierung eines Wertes ist gescheitert.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Das Ergebnis einer Kern-Operation.
pub type Result<T> = std::result::Result<T, Error>;
