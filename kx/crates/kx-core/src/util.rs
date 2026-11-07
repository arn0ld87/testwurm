use crate::Result;
use sha2::{Digest, Sha256};

pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|e| crate::Error::State(format!("base64: {e}")))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(crate::Error::State("hex: ungerade Laenge".into()));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0]).ok_or_else(|| {
            crate::Error::State(format!("hex: ungueltiges Zeichen {}", pair[0] as char))
        })?;
        let lo = hex_val(pair[1]).ok_or_else(|| {
            crate::Error::State(format!("hex: ungueltiges Zeichen {}", pair[1] as char))
        })?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub struct Sha256Stream(Sha256);

impl Sha256Stream {
    pub fn new() -> Self {
        Self(Sha256::new())
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub fn finish(self) -> [u8; 32] {
        let out = self.0.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

impl Default for Sha256Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// Zeitstempel im RFC-3339-Format (Sekunden, UTC). Der Server speichert genau
/// diese Form, damit Journal, Konsole und Audit-Log identische Strings nutzen.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_utc(secs)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sekunden -> RFC 3339 in UTC. Handgerechnet, weil diese Notiz ohne
/// Zeitcrates auskommen muss (Agent-Binaer soll klein und pruefbar bleiben).
pub fn rfc3339_utc(secs: i64) -> String {
    let (days, day_secs) = div_mod_i64(secs, 86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = day_secs / 3600;
    let mm = (day_secs % 3600) / 60;
    let ss = day_secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// RFC 3339 (UTC oder `+HH:MM`) -> Sekunden. Toleriert die `Z`-Form und
/// numerische Zeitzonen, weil der Server beides erzeugen kann.
pub fn parse_rfc3339_secs(text: &str) -> Option<i64> {
    let text = text.trim();
    let (datetime, offset) = split_zone(text)?;
    let (date, time) = datetime.split_once('T').or_else(|| datetime.split_once(' '))?;
    let mut di = date.split('-');
    let y: i64 = di.next()?.parse().ok()?;
    let m: i64 = di.next()?.parse().ok()?;
    let d: i64 = di.next()?.parse().ok()?;
    let mut ti = time.split(':');
    let hh: i64 = ti.next()?.parse().ok()?;
    let mm: i64 = ti.next()?.parse().ok()?;
    let ss: i64 = ti.next().unwrap_or("0").chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()?;
    let days = days_from_civil(y, m as u32, d as u32);
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

fn split_zone(text: &str) -> Option<(&str, i64)> {
    if let Some(rest) = text.strip_suffix('Z') {
        return Some((rest, 0));
    }
    let idx = text.rfind(['+', '-']).filter(|i| *i > 10)?;
    let sign = if text.as_bytes()[idx] == b'-' { -1 } else { 1 };
    let zone = &text[idx + 1..];
    let (hh, mm) = zone.split_once(':').unwrap_or((zone, "0"));
    let hh: i64 = hh.parse().ok()?;
    let mm: i64 = mm.parse().unwrap_or(0);
    Some((&text[..idx], sign * (hh * 3600 + mm * 60)))
}

fn div_mod_i64(a: i64, b: i64) -> (i64, i64) {
    let q = a.div_euclid(b);
    (q, a.rem_euclid(b))
}

/// Howard Hinnant's civil_from_days (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

const CRC_TABLE: [u32; 256] = build_crc_table();

const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// CRC-32 (IEEE, wie gzip). Sichert den Footer gegen einzelne Bitkippen und
/// gegen das Abschieben von Dateienden ohne Neuschreiben des Fusses.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for b in bytes {
        c = CRC_TABLE[((c ^ (*b as u32)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Kanonisches JSON: sortierte Schluessel, keine leerzeichen. Wird fuer
/// Task-Hashes und Anti-Wiederholungs-Fingerabdruecke benutzt (B11 §3).
pub fn canon_json<T: serde::Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_string(&value)?)
}

/// Sicherer Pfadvergleich ohne Case-Sensitive-Falle auf Windows:
/// der Aufrufer uebergibt bereits normalisierte Pfade.
pub fn path_key(path: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        path.to_ascii_lowercase()
    } else {
        path.to_string()
    }
}

/// Ganzzahl-Klammerung.
pub fn clamp(v: u64, lo: u64, hi: u64) -> u64 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Deterministischer Jitter: `base * (1 ± spread)` mit XOR-shift-Quelle.
/// Kein `rand` im Beacon-Pfad, damit der Jitter reproduzierbar protokolliert
/// werden kann (Band 12 §7: Aequidistanz nachweisbar ausschliessen).
pub fn jitter(base_ms: u64, spread: f64, seed: &mut u64) -> u64 {
    if base_ms == 0 {
        return 0;
    }
    // xorshift64*
    let mut x = if *seed == 0 { 0x2545_F491_4F6C_DD1D } else { *seed };
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *seed = x;
    let factor = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) as f64) / (u64::MAX as f64);
    let factor = 1.0 + (factor * 2.0 - 1.0) * spread.clamp(0.0, 0.95);
    ((base_ms as f64) * factor).max(1.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_roundtrip() {
        let s = rfc3339_utc(1_762_483_200);
        assert_eq!(s, "2025-11-07T08:00:00Z", "got {s}");
        assert_eq!(parse_rfc3339_secs(&s), Some(1_762_483_200));
        assert_eq!(parse_rfc3339_secs("2025-11-07T09:00:00+01:00"), Some(1_762_483_200));
    }

    #[test]
    fn epoch_is_1970() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(-86_400), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 15, 16, 255];
        let h = hex(&bytes);
        assert_eq!(h, "00010f10ff");
        assert_eq!(hex_decode(&h).unwrap(), bytes);
    }

    #[test]
    fn b64_roundtrip() {
        let bytes = sha256(b"test");
        assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn jitter_stays_in_band() {
        let mut seed = 42;
        for _ in 0..500 {
            let v = jitter(60_000, 0.25, &mut seed);
            assert!(v >= 45_000 && v <= 75_000, "value {v}");
        }
    }

    #[test]
    fn crc32_matches_known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn canon_json_sorts() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(canon_json(&a).unwrap(), r#"{"a":2,"b":1}"#);
    }
}
