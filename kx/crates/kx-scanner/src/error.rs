//! Fehlerdefinitionen für den Kx-Scanner.

/// Fehler beim ARP-Sweep oder TCP-Scan.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// Netzwerk-Socket konnte nicht geöffnet werden (fehlende Berechtigungen?).
    #[error("Socket-Fehler: {0}")]
    Socket(String),
    /// ARP-Paket konnte nicht gesendet/empfangen werden.
    #[error("ARP-Fehler: {0}")]
    Arp(String),
    /// TCP-Verbindung fehlgeschlagen.
    #[error("TCP-Verbindung fehlgeschlagen: {0}")]
    Tcp(String),
    /// Zeitüberschreitung bei der Verbindung.
    #[error("Zeitüberschreitung: {0}")]
    Timeout(String),
    /// Die Funktion ist auf dieser Plattform nicht verfügbar.
    #[error("Nicht unterstützt: {0}")]
    Unsupported(String),
}
