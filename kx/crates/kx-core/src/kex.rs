//! Die Art des Schlüsselaustauschs.
//!
//! `KexId` stand im Containerformat-Modul — obwohl es nichts mit einem
//! Container zu tun hat, sondern den Schlüsselaustausch des C2-Servers
//! beschreibt. Das war ein Fundort im falschen Modul: wer das Containerformat
//! entfernen will, bricht damit die Kryptografie.
//!
//! Der Bericht vom 2026-11-15 hat genau das festgehalten — „`KexId` ist
//! load-bearing im lebenden Krypto-Pfad". Hier liegt es jetzt an seinem Ort.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum KexId {
    /// Nur X25519, fallback fuer Umgebungen ohne ML-KEM (Entscheidung E3).
    X25519 = 0,
    /// Hybride KEM X25519 + ML-KEM-768, Shared Secret ueber HKDF kombiniert.
    HybridX25519MlKem768 = 1,
}

impl KexId {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(KexId::X25519),
            1 => Ok(KexId::HybridX25519MlKem768),
            other => Err(Error::Format(format!("KEX-Kennung {other} unbekannt"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Die Kennung hat einen festen Wert im Wire-Format — der Footer traegt
    /// sie als Byte. Ein Verschieben der Werte wuerde die gespeicherten
    /// Container unlesbar machen.
    #[test]
    fn die_kennung_hat_feste_werte() {
        assert_eq!(KexId::X25519 as u8, 0);
        assert_eq!(KexId::HybridX25519MlKem768 as u8, 1);
        assert_eq!(KexId::from_u8(0).expect("X25519"), KexId::X25519);
        assert_eq!(
            KexId::from_u8(1).expect("Hybrid"),
            KexId::HybridX25519MlKem768
        );
        assert!(
            KexId::from_u8(2).is_err(),
            "eine unbekannte Kennung muss scheitern"
        );
    }
}
