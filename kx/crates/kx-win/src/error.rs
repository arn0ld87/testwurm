//! Fehlerdefinitionen für Windows-Post-Exploitation.

/// Fehler bei Secrets-Extraktion oder Persistence.
#[derive(Debug, thiserror::Error)]
pub enum WinError {
    /// Externes Tool (mimikatz, PowerShell) nicht gefunden.
    #[error("Tool nicht verfügbar: {0}")]
    ToolMissing(String),
    /// Subprozess lieferte einen Fehler.
    #[error("Tool fehlgeschlagen (Code {0}): {1}")]
    ToolFailed(i32, String),
    /// Registry-Zugriff fehlgeschlagen.
    #[error("Registry-Fehler: {0}")]
    Registry(String),
    /// Scheduled-Task-Erstellung fehlgeschlagen.
    #[error("Scheduled-Task-Fehler: {0}")]
    ScheduledTask(String),
    /// Dienst-Installation fehlgeschlagen.
    #[error("Dienst-Fehler: {0}")]
    Service(String),
}
