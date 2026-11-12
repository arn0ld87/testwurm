//! POSIX-Persistenz: systemd-Dienste und Cron-Jobs.
//!
//! Installiert den Agent als systemd-Dienst (boot-time) oder Cron-Job
//! (zeitgesteuert) auf Linux/Unix-Systemen.

use std::path::{Path, PathBuf};
use tracing::{debug, warn};

use crate::error::PosixError;

/// Verzeichnis, in dem die Environment-Dateien der Dienste liegen.
///
/// Bewusst nicht in `/etc/systemd/system/`: dort liest systemd jede Datei mit
/// `.service`-Endung als Unit, und das Verzeichnis ist für andere lesbar.
pub const ENV_DIR: &str = "/etc/kx";

/// Ein systemd-Dienst, der installiert werden soll.
#[derive(Debug, Clone)]
pub struct SystemdService {
    /// Name des Dienstes (z.B. "kx-agent"). Bestimmt Dateinamen und
    /// systemctl-Namen.
    pub name: String,
    /// Pfad zur ausführbaren Datei.
    pub binary_path: PathBuf,
    /// Argumente für `ExecStart`, ohne das Binary selbst.
    ///
    /// Ein `${NAME}`-Platzhalter wird von systemd aus der Environment-Datei
    /// aufgelöst. Damit steht kein Geheimnis im Klartext in der Unit-Datei,
    /// die für jeden lesbar ist, der die Datei lesen darf.
    pub args: Vec<String>,
    /// Umgebungsvariablen für die Environment-Datei (KEY=VALUE). Sie landen in
    /// einer Datei mit restriktiven Rechten, nicht in der Unit-Datei.
    pub env: Vec<(String, String)>,
}

/// Pfad der Environment-Datei eines Dienstes.
pub fn systemd_env_file_path(service_name: &str) -> PathBuf {
    Path::new(ENV_DIR).join(format!("{service_name}.env"))
}

/// Baut den Inhalt der Environment-Datei.
///
/// Der Inhalt ist `KEY=VALUE` pro Zeile — das Format, das systemd für
/// `EnvironmentFile=` erwartet.
pub fn systemd_env_content(svc: &SystemdService) -> String {
    let mut out = String::new();
    for (key, value) in &svc.env {
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// Baut den Inhalt der systemd-Unit-Datei.
///
/// Die Unit nennt die Environment-Datei, aber nicht deren Werte. Ein
/// `${NAME}`-Platzhalter im `ExecStart` wird von systemd zur Laufzeit aus
/// dieser Datei aufgelöst.
///
/// `Restart=always` zusammen mit fehlenden Pflichtargumenten erzeugt eine
/// Neustart-Schleife — deshalb enthält der `ExecStart` alle Argumente, die der
/// Agent braucht.
pub fn systemd_unit_content(svc: &SystemdService) -> String {
    let path = svc.binary_path.to_string_lossy();
    let env_path = systemd_env_file_path(&svc.name);
    let env_path = env_path.to_string_lossy();
    let args = svc.args.join(" ");
    format!(
        r#"[Unit]
Description=Kx persistent agent ({name})
After=network-online.target

[Service]
Type=simple
EnvironmentFile={env_path}
ExecStart={path} {args}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
        name = svc.name,
    )
}

/// Installiert einen systemd-Systemdienst.
///
/// # Argumente
/// * `svc` — Dienst mit Binary-Pfad, Argumenten und Umgebungsvariablen.
///
/// Schreibt zwei Dateien: die Unit-Datei (die Werte des Tokens stehen *nicht*
/// darin) und die Environment-Datei mit restriktiven Rechten (0600 in einem
/// Verzeichnis mit 0700).
#[cfg(unix)]
pub async fn install_systemd_service(svc: &SystemdService) -> Result<(), PosixError> {
    let unit_dir = Path::new("/etc/systemd/system");
    let env_dir = Path::new(ENV_DIR);

    // Verzeichnis für die Environment-Datei anlegen (0700 — nur root).
    std::fs::create_dir_all(env_dir).map_err(|e| PosixError::Systemd(e.to_string()))?;
    set_mode(env_dir, 0o700)?;

    // Environment-Datei ZUERST schreiben: existiert sie beim Start des
    // Dienstes nicht, schlägt systemd mit einem klaren Fehler fehl, statt
    // den Agenten mit leerem Token zu starten.
    let env_path = systemd_env_file_path(&svc.name);
    std::fs::write(&env_path, systemd_env_content(svc))
        .map_err(|e| PosixError::Systemd(e.to_string()))?;
    set_mode(&env_path, 0o600)?;

    let unit_path = unit_dir.join(format!("{}.service", svc.name));
    std::fs::write(&unit_path, systemd_unit_content(svc))
        .map_err(|e| PosixError::Systemd(e.to_string()))?;

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
        .args(["enable", &svc.name])
        .output()
        .await
        .map_err(|e| PosixError::Systemd(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(PosixError::Systemd(err));
    }
    debug!(
        "systemd-Dienst {name} installiert und aktiviert",
        name = svc.name
    );
    Ok(())
}

/// Setzt die Zugriffsrechte einer Datei oder eines Verzeichnisses.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), PosixError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| PosixError::Systemd(e.to_string()))?
        .permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|e| PosixError::Systemd(e.to_string()))
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
        return Err(PosixError::Cron(
            "crontab-Aktualisierung fehlgeschlagen".into(),
        ));
    }
    debug!("Cron-Persistenz installiert");
    Ok(())
}

// Nicht-Unix-Plattformen: Fehler-Implementierungen.
#[cfg(not(unix))]
pub async fn install_systemd_service(_svc: &SystemdService) -> Result<(), PosixError> {
    Err(PosixError::Systemd(
        "nicht auf dieser Plattform verfügbar".into(),
    ))
}

#[cfg(not(unix))]
pub async fn write_cron_persistence(_minute: i32, _command: &str) -> Result<(), PosixError> {
    Err(PosixError::Cron(
        "nicht auf dieser Plattform verfügbar".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_service() -> SystemdService {
        SystemdService {
            name: "kx-agent".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/kx-agent"),
            args: vec![
                "--server".to_string(),
                "${KX_C2_URL}".to_string(),
                "--token".to_string(),
                "${KX_C2_TOKEN}".to_string(),
                "--server-cert".to_string(),
                "/etc/kx/server.pem".to_string(),
                "--start".to_string(),
                "192.168.1.1".to_string(),
                "--end".to_string(),
                "192.168.1.254".to_string(),
            ],
            env: vec![
                ("KX_C2_URL".to_string(), "https://c2.local:8443".to_string()),
                ("KX_C2_TOKEN".to_string(), "geheim-token".to_string()),
            ],
        }
    }

    /// Der ExecStart enthält alle Pflichtargumente.
    ///
    /// Vor dem Fix war der `ExecStart` leer (`install_systemd_service("kx-agent",
    /// &exe, "")`). Der Agent startete nie, `Restart=always` sorgte für eine
    /// Neustart-Schleife.
    #[test]
    fn unit_exec_start_carries_every_required_argument() {
        let unit = systemd_unit_content(&sample_service());
        let exec = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("ExecStart-Zeile");
        for arg in ["--server", "--token", "--server-cert", "--start", "--end"] {
            assert!(
                exec.contains(arg),
                "der ExecStart nennt {arg} nicht: {exec}"
            );
        }
        // Der Pfad zum Binary steht vorn.
        assert!(exec.starts_with("ExecStart=/usr/local/bin/kx-agent "));
    }

    /// Das Token steht nicht im Klartext in der Unit-Datei.
    ///
    /// Die Unit-Datei unter `/etc/systemd/system/` ist für jeden lesbar, der
    /// die Datei lesen darf.
    #[test]
    fn unit_does_not_contain_the_token_in_plaintext() {
        let unit = systemd_unit_content(&sample_service());
        assert!(
            !unit.contains("geheim-token"),
            "das Token steht im Klartext in der Unit-Datei"
        );
        // Es wird als Platzhalter referenziert, den systemd auflöst.
        assert!(unit.contains("${KX_C2_TOKEN}"));
    }

    /// Die Unit referenziert die Environment-Datei.
    #[test]
    fn unit_references_the_environment_file() {
        let unit = systemd_unit_content(&sample_service());
        assert!(unit.contains("EnvironmentFile=/etc/kx/kx-agent.env"));
    }

    /// Der Token steht in der Environment-Datei, im Format das systemd erwartet.
    #[test]
    fn env_file_carries_the_token() {
        let env = systemd_env_content(&sample_service());
        assert!(env.contains("KX_C2_TOKEN=geheim-token\n"));
        assert!(env.contains("KX_C2_URL=https://c2.local:8443\n"));
        // KEY=VALUE pro Zeile, nichts anderes.
        for line in env.lines() {
            assert!(line.contains('='), "Zeile ohne KEY=VALUE: {line}");
        }
    }

    /// Der Pfad der Environment-Datei liegt nicht im systemd-Unit-Verzeichnis.
    ///
    /// Dort liest systemd jede `.service`-Datei als Unit, und das Verzeichnis
    /// ist für andere lesbar.
    #[test]
    fn env_file_lives_outside_the_unit_directory() {
        let path = systemd_env_file_path("kx-agent");
        assert!(path.starts_with("/etc/kx/"));
        assert!(!path.starts_with("/etc/systemd/system/"));
    }
}
