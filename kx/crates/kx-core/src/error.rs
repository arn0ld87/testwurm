use std::fmt;

/// Fehlerklassen nach Band 08 §8. Die Klassen sind absichtlich stabil,
/// weil Konsolen-Fehlerliste und Journal danach gefiltert und zaehlt werden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErrorClass {
    /// Pfad nicht gefunden oder Wettrennen beim Enumerieren (Win 2/3, POSIX ENOENT).
    NotFound,
    /// ACL/Privileg fehlt (Win 5, POSIX EACCES/EPERM).
    Access,
    /// Anderer Prozess haelt ein exklusives Handle (Win 32, POSIX EAGAIN).
    Sharing,
    /// Datei ist vom Abbildungsloader gemappt (Win 1224, POSIX ETXTBSY).
    UserMapped,
    /// Datentraeger voll (Win 112, POSIX ENOSPC). Fuehrt zum Totalabbruch (E003).
    DiskFull,
    /// Netzwerkpfad nicht erreichbar (Win 53/64, ENOTCONN auf SMB-Mount).
    Network,
    /// Eingabe-/Ausgabegroesse oder Pfadform ungueltig.
    InvalidInput,
    /// Puffer zu klein, Struktur zu gross — treatierbar, kein Datenverlust.
    BufferTooSmall,
    /// Krypto-/Formatfehler: Tag-Pruefung geschlagen, Header defekt.
    Crypto,
    /// Journal-/Manifestinkonsistenz.
    State,
    /// Alles uebrige. Kommt mit Rohtext in die Fehlerliste.
    Other,
}

impl ErrorClass {
    /// Abbruchwuerdig? DiskFull beendet den Lauf, ein halbvoller Lauf ohne
    /// Platz ist nicht sinnvoll fortsetzbar (E003).
    pub fn aborts_run(self) -> bool {
        matches!(self, ErrorClass::DiskFull)
    }

    /// Wiederholbar mit Backoff? Blockierte Dateien nach N Versuchen aufgeben (E002).
    pub fn retryable(self) -> bool {
        matches!(
            self,
            ErrorClass::Sharing | ErrorClass::UserMapped | ErrorClass::Network
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::NotFound => "not_found",
            ErrorClass::Access => "access",
            ErrorClass::Sharing => "sharing",
            ErrorClass::UserMapped => "user_mapped",
            ErrorClass::DiskFull => "disk_full",
            ErrorClass::Network => "network",
            ErrorClass::InvalidInput => "invalid_input",
            ErrorClass::BufferTooSmall => "buffer_too_small",
            ErrorClass::Crypto => "crypto",
            ErrorClass::State => "state",
            ErrorClass::Other => "other",
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io {class}: {path}: {message}")]
    Io {
        class: ErrorClass,
        path: String,
        message: String,
        /// Roher OS-Fehlercode, falls verfuegbar (GetLastError bzw. errno).
        raw: Option<i64>,
    },

    #[error("krypto: {0}")]
    Crypto(String),

    #[error("format: {0}")]
    Format(String),

    #[error("zustand: {0}")]
    State(String),

    #[error("konfiguration: {0}")]
    Config(String),

    #[error("plattform {os}: {message}")]
    Platform { os: &'static str, message: String },

    #[error("steuerstrecke: {0}")]
    Transport(String),

    #[error("abgebrochen")]
    Aborted,

    #[error("pause angefordert")]
    Paused,

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

impl Error {
    pub fn io(class: ErrorClass, path: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Io {
            class,
            path: path.into(),
            message: message.into(),
            raw: None,
        }
    }

    pub fn io_raw(
        class: ErrorClass,
        path: impl Into<String>,
        message: impl Into<String>,
        raw: i64,
    ) -> Self {
        Error::Io {
            class,
            path: path.into(),
            message: message.into(),
            raw: Some(raw),
        }
    }

    /// Klassifizierung aus einem std::io::Error: plattformneutral ueber den
    /// Error-Katalog. Windows-NTSTATUS-Werte werden in `kx-win` uebersetzt,
    /// weil `raw_os_error()` dort die Win32-Formatmessage-Codes traegt.
    pub fn from_io(path: impl Into<String>, err: &std::io::Error) -> Self {
        let path = path.into();
        let class = class_from_errkind(err.kind(), err.raw_os_error());
        Error::Io {
            class,
            path,
            message: err.to_string(),
            raw: err.raw_os_error().map(|v| v as i64),
        }
    }

    pub fn class(&self) -> ErrorClass {
        match self {
            Error::Io { class, .. } => *class,
            Error::Crypto(_) | Error::Format(_) => ErrorClass::Crypto,
            Error::State(_) => ErrorClass::State,
            Error::Config(_) => ErrorClass::InvalidInput,
            Error::Transport(_) => ErrorClass::Network,
            Error::Aborted | Error::Paused => ErrorClass::Other,
            Error::Serde(_) => ErrorClass::State,
            Error::Platform { .. } => ErrorClass::Other,
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Error::Io { path, .. } if !path.is_empty() => Some(path),
            _ => None,
        }
    }
}

pub fn class_from_errkind(kind: std::io::ErrorKind, raw: Option<i32>) -> ErrorClass {
    use std::io::ErrorKind as K;
    // POSIX-errno zuerst: die Klassen sind auf beiden Plattformen identisch
    // benannt, nur die Zahlen sind verschieden.
    if let Some(code) = raw {
        #[cfg(unix)]
        {
            const EACCES: i32 = 13;
            const EPERM: i32 = 1;
            const ENOENT: i32 = 2;
            const ENOSPC: i32 = 28;
            const EAGAIN: i32 = 11;
            const ETXTBSY: i32 = 26;
            const EBUSY: i32 = 16;
            const ENOTCONN: i32 = 107;
            const EHOSTUNREACH: i32 = 113;
            const ENETDOWN: i32 = 100;
            match code {
                EACCES | EPERM => return ErrorClass::Access,
                ENOENT => return ErrorClass::NotFound,
                ENOSPC => return ErrorClass::DiskFull,
                EAGAIN | EBUSY => return ErrorClass::Sharing,
                ETXTBSY => return ErrorClass::UserMapped,
                ENOTCONN | EHOSTUNREACH | ENETDOWN => return ErrorClass::Network,
                _ => {}
            }
        }
        #[cfg(windows)]
        {
            // Win32-Fehlercodes, wie sie CreateFileW/ReadFile ueber
            // GetLastError melden. Vollstaendige Liste in kx-win::winerr.
            const ERROR_FILE_NOT_FOUND: i32 = 2;
            const ERROR_PATH_NOT_FOUND: i32 = 3;
            const ERROR_ACCESS_DENIED: i32 = 5;
            const ERROR_SHARING_VIOLATION: i32 = 32;
            const ERROR_LOCK_VIOLATION: i32 = 33;
            const ERROR_NOT_ENOUGH_MEMORY: i32 = 8;
            const ERROR_DISK_FULL: i32 = 39;
            const ERROR_HANDLE_DISK_FULL: i32 = 39;
            const ERROR_USER_MAPPED_FILE: i32 = 1224;
            const ERROR_BAD_NETPATH: i32 = 53;
            const ERROR_NETWORK_UNREACHABLE: i32 = 1231;
            const ERROR_NETNAME_DELETED: i32 = 64;
            match code {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => return ErrorClass::NotFound,
                ERROR_ACCESS_DENIED => return ErrorClass::Access,
                ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => return ErrorClass::Sharing,
                ERROR_USER_MAPPED_FILE => return ErrorClass::UserMapped,
                ERROR_DISK_FULL | ERROR_NOT_ENOUGH_MEMORY => return ErrorClass::DiskFull,
                ERROR_BAD_NETPATH | ERROR_NETNAME_DELETED | ERROR_NETWORK_UNREACHABLE => {
                    return ErrorClass::Network
                }
                _ => {}
            }
        }
    }
    match kind {
        K::NotFound => ErrorClass::NotFound,
        K::PermissionDenied => ErrorClass::Access,
        K::AlreadyExists | K::WouldBlock => ErrorClass::Sharing,
        K::StorageFull | K::OutOfMemory => ErrorClass::DiskFull,
        K::NotConnected
        | K::ConnectionRefused
        | K::ConnectionReset
        | K::BrokenPipe
        | K::TimedOut => ErrorClass::Network,
        K::InvalidInput | K::InvalidData => ErrorClass::InvalidInput,
        K::Unsupported => ErrorClass::Other,
        _ => ErrorClass::Other,
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_stable_strings() {
        assert_eq!(ErrorClass::DiskFull.as_str(), "disk_full");
        assert!(ErrorClass::DiskFull.aborts_run());
        assert!(!ErrorClass::Access.aborts_run());
        assert!(ErrorClass::Sharing.retryable());
        assert!(!ErrorClass::NotFound.retryable());
    }

    #[test]
    fn disk_full_aborts_and_maps() {
        let err = Error::io_raw(ErrorClass::DiskFull, "/x", "voll", 112);
        assert_eq!(err.class(), ErrorClass::DiskFull);
        assert_eq!(err.path(), Some("/x"));
        assert!(class_from_errkind(std::io::ErrorKind::StorageFull, None).aborts_run());
    }
}
