//! Die Textkodierungen: Base64 und Hex.
//!
//! Beide werden an mehreren Stellen gebraucht: das versiegelte
//! Master-Key-Material und die Beute des Agenten gehen als Base64 über die
//! Leitung, die Fingerabdrücke der Schlüssel als Hex.
//!
//! Sie standen in einer Sammlung mit neun weiteren Helfern, die niemand
//! aufrief. Jetzt sind sie ein Modul mit einem Namen.

use crate::Result;

/// Kodiert Bytes als Base64 (Standard-Alphabet, mit Füllung).
pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Dekodiert Base64. Whitespace am Rand wird ignoriert.
pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|e| crate::Error::State(format!("base64: {e}")))
}

/// Kodiert Bytes als Hex (kleinbuchstaben).
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        let bytes = [0u8, 1, 15, 16, 255, 128];
        assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn hex_kodiert_kleinbuchstaben() {
        let bytes = [0u8, 1, 15, 16, 255];
        assert_eq!(hex(&bytes), "00010f10ff");
    }
}
