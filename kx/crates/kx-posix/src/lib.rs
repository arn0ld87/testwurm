//! kx-posix: POSIX-Post-Exploitation für autorisierte Penetrationstests.
//!
//! Enthält Module zur Secrets-Extraktion (/etc/shadow, SSH-Keys, AWS) und
//! Persistence (systemd-Dienste, Cron-Jobs) auf Linux/Unix-Systemen.
//!
//! Alle Funktionen sind cross-platform kompilierbar; die echte Logik läuft
//! nur auf Unix-Plattformen (via `cfg(unix)`).

pub mod error;
pub mod persist;
pub mod secrets;

pub use error::PosixError;
pub use persist::{
    install_systemd_service, systemd_env_content, systemd_env_file_path, systemd_unit_content,
    write_cron_persistence, SystemdService, ENV_DIR,
};
pub use secrets::{extract_aws_credentials, extract_shadow_hashes, extract_ssh_keys, Secret};
