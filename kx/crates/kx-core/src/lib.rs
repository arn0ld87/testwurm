//! kx-core — plattformneutraler Kern des Encoder-Projekts.
//!
//! Schichtgrenzen (Abhängigkeitsrichtung ist vorgegeben, Band 14 §1):
//! `format` → `crypto` → `engine` → `beacon`. Das Beacon kennt den Encoder,
//! der Encoder kennt kein Beacon.
//!
//! Alles hier ist Plattformcode-frei: Windows- und POSIX-Spezifika stecken in
//! `platform::PlatformHooks`, implementiert in `kx-win` und `kx-posix`.

pub mod beacon;
pub mod crypto;
pub mod engine;
pub mod entropy;
pub mod error;
pub mod format;
pub mod hostkey;
pub mod journal;
pub mod manifest;
pub mod platform;
pub mod scan;
pub mod util;

pub use error::{Error, Result};

/// Formatversion, die dieser Build lesen und schreiben kann (B005).
pub const FORMAT_VERSION: u8 = 1;
/// Aeltere Formatversionen, die dieser Build noch lesen kann.
pub const READABLE_FORMAT_VERSIONS: [u8; 1] = [1];

/// Bezeichnung des Datenformats fuer Werkzeuge und Doku.
pub const FORMAT_NAME: &str = "KXENC";

/// Maximale Anzahl verschluesselter Bereiche pro Datei (Kopf + Fussteil).
/// Der Wert ist konstant, damit das Format keine variable Laenge im Footer traegt.
pub const MAX_RANGES: usize = 2;
