//! kx-win: Windows-Post-Exploitation für autorisierte Penetrationstests.
//!
//! Enthält Module zur Secrets-Extraktion (Credential Manager, LSASS, Browser)
//! und Persistence (Scheduled Tasks, Registry, Windows-Dienste).
//!
//! Alle Funktionen sind cross-platform kompilierbar; die echte Logik läuft
//! nur auf Windows (via `cfg(target_os = "windows")`).

pub mod error;
pub mod persist;
pub mod secrets;

pub use error::WinError;
pub use persist::{create_registry_run_key, create_scheduled_task, install_service, start_service};
pub use secrets::{extract_browser_credentials, extract_credential_manager, extract_lsass, Secret};
