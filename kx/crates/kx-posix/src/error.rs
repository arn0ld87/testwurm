//! Fehlerdefinitionen für POSIX-Post-Exploitation.

/// Fehler bei Secrets-Extraktion oder Persistence auf Linux/Unix-Systemen.
#[derive(Debug, thiserror::Error)]
pub enum PosixError {
    /// Externes Tool (shadow, ssh-keygen, systemd) nicht gefunden.
    #[error("Tool nicht verfügbar: {0}")]
    ToolMissing(String),
    /// Subprozess lieferte einen Fehler.
    #[error("Tool fehlgeschlagen (Code {0}): {1}")]
    ToolFailed(i32, String),
    /// Datei- oder Verzeichnis-Zugriff fehlgeschlagen.
    #[error("Dateizugriff fehlgeschlagen: {0}")]
    FileAccess(String),
    /// systemd-Dienst-Installation fehlgeschlagen.
    #[error("systemd-Fehler: {0}")]
    Systemd(String),
    /// Cron-Persistenz fehlgeschlagen.
    #[error("Cron-Fehler: {0}")]
    Cron(String),
}
