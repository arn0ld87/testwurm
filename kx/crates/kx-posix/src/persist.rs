//! POSIX-Persistenz: systemd-Dienste und Cron-Jobs.
//!
//! Installiert den Agent als systemd-Dienst (boot-time) oder Cron-Job
//! (zeitgesteuert) auf Linux/Unix-Systemen.

use std::path::Path;
use tracing::{debug, warn};

use crate::error::PosixError;

/// Installiert einen systemd-Systemdienst für den angegebenen Binary-Pfad.
///
/// # Argumente
/// * `service_name` — Name des Dienstes (z.B. "kx-agent").
/// * `binary_path`  — Pfad zur ausführbaren Datei.
/// * `command`      — vollständiger Befehl inkl. Argumente.
#[cfg(unix)]
pub async fn install_systemd_service(
    service_name: &str,
    binary_path: &Path,
    command: &str,
) -> Result<(), PosixError> {
    let path = binary_path
        .to_str()
        .ok_or_else(|| PosixError::Systemd("ungültiger Pfad".into()))?;
    let unit = format!(
        r#"[Unit]
Description=Kx persistent agent ({service_name})
After=network-online.target

[Service]
Type=simple
ExecStart={path} {command}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#
    );
    let unit_path = format!("/etc/systemd/system/{service_name}.service");
    std::fs::write(&unit_path, &unit).map_err(|e| PosixError::Systemd(e.to_string()))?;
    // systemctl daemon-reload && systemctl enable
    let out = tokio::process::Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .await
        .map_err(|e| PosixError::Systemd(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        warn!("systemctl daemon-reload fehlgeschlagen: {err}");
        return Err(PosixError::Systemd(err));
    }
    let out = tokio::process::Command::new("systemctl")
        .args(["enable", service_name])
        .output()
        .await
        .map_err(|e| PosixError::Systemd(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(PosixError::Systemd(err));
    }
    debug!("systemd-Dienst {service_name} installiert und aktiviert");
    Ok(())
}

/// Schreibt eine Cron-Persistenz (root-Crontab) für den angegebenen Befehl.
///
/// # Argumente
/// * `minute`  — Minute (0-59), "-1" für @reboot.
/// * `command` — vollständiger Befehl inkl. Argumente.
#[cfg(unix)]
pub async fn write_cron_persistence(minute: i32, command: &str) -> Result<(), PosixError> {
    let cron_line = if minute < 0 {
        format!("@reboot {command}")
    } else {
        format!("{minute} * * * * {command}")
    };
    // Bestehende Crontab laden, Duplikate vermeiden.
    let existing = tokio::process::Command::new("crontab")
        .arg("-l")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    if existing.contains(command) {
        debug!("Cron-Eintrag bereits vorhanden");
        return Ok(());
    }
    let new_cron = format!("{existing}\n{cron_line}\n");
    let mut child = tokio::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| PosixError::Cron(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(new_cron.as_bytes())
            .await
            .map_err(|e| PosixError::Cron(e.to_string()))?;
    }
    let status = child
        .wait()
        .await
        .map_err(|e| PosixError::Cron(e.to_string()))?;
    if !status.success() {
        return Err(PosixError::Cron("crontab-Aktualisierung fehlgeschlagen".into()));
    }
    debug!("Cron-Persistenz installiert");
    Ok(())
}

// Nicht-Unix-Plattformen: Fehler-Implementierungen.
#[cfg(not(unix))]
pub async fn install_systemd_service(
    _service_name: &str,
    _binary_path: &Path,
    _command: &str,
) -> Result<(), PosixError> {
    Err(PosixError::Systemd("nicht auf dieser Plattform verfügbar".into()))
}

#[cfg(not(unix))]
pub async fn write_cron_persistence(_minute: i32, _command: &str) -> Result<(), PosixError> {
    Err(PosixError::Cron("nicht auf dieser Plattform verfügbar".into()))
}
