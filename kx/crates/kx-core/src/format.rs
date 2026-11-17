//! Dateiformat `KXENC` v1 — Layout, Reichweitenplanung, Nonce- und AAD-Regeln.
//!
//! **Hier wird nichts verschluesselt.** Dieses Modul ist der Formatvertrag:
//! Wo die Bytes liegen, wie die Chunks nummeriert sind, wie die Nonce und die
//! AAD entstehen. Die Chiffre sitzt in [`crate::kxenc`] — sie dockt genau hier
//! an (`nonce_for`, `aad_for`) und benutzt diese Funktionen, statt sie zu
//! duplizieren. Die Chunk-Maschinerie (`chunk_iter`, `aad_for`, `nonce_for`,
//! `ChunkRef`, `ChunkContext`) ist deshalb crate-intern; oeffentlich bleibt der
//! Vertrag: Fusszeile, Reichweite, Flags und die Planung.
//!
//! Layout nach dem Verschlüsseln (alles in Byte, LE-Zahlen im Footer):
//!
//! ```text
//! 0                head_ciphertext            (in Place, gleiche Laenge wie Klartext)
//! hl               middle_plaintext           (unberuehrt, Entropie-/Groessenschwelle)
//! P - tl           tail_ciphertext            (in Place, gleiche Laenge)
//! P                tags, 16 Byte je Chunk     (append, detached)
//! P + tags_len     footer, 320 Byte, Klartext (append)
//! ```
//!
//! Warum dieses Layout (freie Einordnung, belegt durch Band 08 §6, Band 18 §3):
//! - **Kein Umschreiben des Mittelfelds.** AEAD vergroessert pro Chunk um 16 Byte.
//!   Wuerde man Header vorne einschieben, muesste der ganze Dateiinhalt verschoben
//!   werden — bei Teilverschuesselung genau der teure Teil. Abgetrennte Tags im
//!   Anhang halten die Schreibzugriffe auf `head + tail + append` begrenzt.
//! - **Footer statt Header.** Der Kopf liegt in der verschluesselten Reichweite.
//!   Ein Fuss am Dateiende ist ohne Entschluesselung lesbar und macht den
//!   Restore ohne Manifest moeglich (B006).
//! - **Detached-Tags statt Attached.** Ein Chunk-Ciphertext hat damit exakt die
//!   Laenge des Klartexts; die Reichweitenplanung bleibt eindeutig (Risiko R2).
use crate::codec::hex;
use crate::kex::KexId;
use crate::{Error, Result, FORMAT_VERSION, MAX_RANGES};

pub const FOOTER_MAGIC: [u8; 4] = *b"KXNF";
pub const FOOTER_LEN: usize = 320;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const DEK_LEN: usize = 32;
pub const HOST_ID_LEN: usize = 16;
pub const BUILD_ID_LEN: usize = 16;
pub const FILE_ID_LEN: usize = 16;
/// Wrapped DEK = Nonce (12) || Chiffriertext (DEK 32 + Nonce-Basis 12) || Tag (16).
pub const WRAPPED_DEK_LEN: usize = NONCE_LEN + DEK_LEN + NONCE_LEN + TAG_LEN;

/// Footer-Feldoffsets. Jede Aenderung ist eine Formatversion, kein Patch.
mod off {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 4;
    pub const CIPHER: usize = 5;
    pub const KEX: usize = 6;
    pub const FLAGS: usize = 7;
    pub const CHUNK_SIZE: usize = 8;
    pub const N_RANGES: usize = 12;
    pub const N_CHUNKS: usize = 16;
    pub const FILE_ID: usize = 20;
    pub const PLAIN_SIZE: usize = 36;
    pub const TAGS_LEN: usize = 44;
    pub const CT_TOTAL: usize = 52;
    pub const RANGE0: usize = 60;
    /// Der Abstand zwischen zwei Range-Eintraegen im Footer.
    pub const RANGE_STRIDE: usize = 24;
    pub const RANGE1: usize = RANGE0 + RANGE_STRIDE;
    pub const WRAPPED_DEK: usize = 108;
    pub const NONCE_BASE: usize = 180;
    pub const RANGE_SHA: usize = 192;
    pub const HOST_ID: usize = 224;

    /// Die Offsets der Range-Eintraege im Footer. Der Footer traegt genau
    /// `MAX_RANGES` Eintraege — deshalb passt die Zahl in ein Array.
    pub const RANGE_OFFS: [usize; crate::MAX_RANGES] = [RANGE0, RANGE1];
    pub const BUILD_ID: usize = 240;
    pub const CREATED: usize = 256;
    pub const CRC: usize = 264;
    pub const CRC_COVER: usize = 264;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum CipherId {
    /// ChaCha20-Poly1305 mit abgetrennten Tags (Default).
    ChaCha20Poly1305Detached = 1,
}

impl CipherId {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(CipherId::ChaCha20Poly1305Detached),
            other => Err(Error::Format(format!(
                "Cipher-Kennung {other} nicht unterstuetzt (Format {FORMAT_VERSION})"
            ))),
        }
    }
}

// `KexId` stand hier ein zweites Mal — obwohl der Schluesselaustausch nichts
// mit einem Container zu tun hat. Der Bericht vom 2026-11-15 hat das als
// Fussnote festgehalten: wer das Containerformat entfernt, bricht damit die
// Kryptografie. `kex.rs` traegt das Enum seit dem Umbau; die Dublette hier
// war tote Kopie (niemand ausserhalb dieses Moduls hat sie benutzt) und ist
// weg. Die Fusszeile verweist jetzt auf `crate::kex::KexId` — die Kennung im
// Byte bleibt dieselbe.

/// Footer-Flags. Bewusst 8 Bit, damit spaetere Versionen Platz haben.
/// Handgeschrieben statt `bitflags`-Crate: der Core soll ohne Makro-Crate
/// kompilieren, und die Bitwerte sind fester Bestandteil des Formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct FooterFlags(pub u8);

impl FooterFlags {
    /// Reichweiten wurden verschluesselt, Tags fehlen (Abbruch mitten im Lauf).
    pub const PARTIAL: u8 = 1;
    /// Dateiendung wurde angehaengt.
    pub const RENAMED: u8 = 2;
    /// zusaetzlicher Passphrase-Pfad (Argon2id) auf den Master Key.
    pub const PASSPHRASE: u8 = 4;
    /// Lock-only: keine Daten geschrieben, nur Handles gehalten.
    pub const LOCK_ONLY: u8 = 8;

    pub const fn empty() -> Self {
        FooterFlags(0)
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, mask: u8) -> bool {
        self.0 & mask == mask
    }
    pub fn insert(&mut self, mask: u8) {
        self.0 |= mask;
    }
    pub fn remove(&mut self, mask: u8) {
        self.0 &= !mask;
    }
    /// Menschlich lesbare Liste fuer Konsole und Audit-Log.
    pub fn describe(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.contains(Self::PARTIAL) {
            v.push("partial");
        }
        if self.contains(Self::RENAMED) {
            v.push("renamed");
        }
        if self.contains(Self::PASSPHRASE) {
            v.push("passphrase");
        }
        if self.contains(Self::LOCK_ONLY) {
            v.push("lock_only");
        }
        v
    }
}

impl From<u8> for FooterFlags {
    fn from(v: u8) -> Self {
        FooterFlags(v)
    }
}

/// Eine verschluesselte Reichweite. Adressen in **Klartextraum**, plus die
/// Absprungposition im Chiffriertext. Beide Angaben sind Pflicht, weil die
/// Groesse aus der Dateigroesse nach Teilverschuesselung nicht ableitbar ist (R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Range {
    pub plain_off: u64,
    pub plain_len: u64,
    pub ct_off: u64,
}

impl Range {
    pub fn is_empty(&self) -> bool {
        self.plain_len == 0
    }
}

/// Der Footer: alles, was ein Restore ohne Manifest braucht (B006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    pub format_version: u8,
    pub cipher: CipherId,
    pub kex: KexId,
    pub flags: FooterFlags,
    pub chunk_size: u32,
    pub n_chunks: u32,
    pub file_id: [u8; FILE_ID_LEN],
    pub plain_size: u64,
    pub tags_len: u64,
    pub ct_total: u64,
    pub ranges: [Range; MAX_RANGES],
    pub wrapped_dek: Vec<u8>,
    pub nonce_base: [u8; NONCE_LEN],
    pub range_sha256: [u8; 32],
    pub host_id: [u8; HOST_ID_LEN],
    pub build_id: [u8; BUILD_ID_LEN],
    pub created_unix: i64,
}

impl Footer {
    pub fn empty_ranges() -> [Range; MAX_RANGES] {
        [Range::default(), Range::default()]
    }

    pub fn ranges_active(&self) -> Vec<Range> {
        self.ranges
            .iter()
            .copied()
            .filter(|r| !r.is_empty())
            .collect()
    }

    /// Prueft die internen Konsistenzzusagen. Wird beim Parsen und vor dem
    /// Schreiben gerufen, damit ein defekter Footer nie in die Engine laeuft.
    pub fn validate(&self) -> Result<()> {
        if self.format_version > FORMAT_VERSION {
            return Err(Error::Format(format!(
                "Formatversion {} kann dieser Build nicht lesen (max {})",
                self.format_version, FORMAT_VERSION
            )));
        }
        if self.format_version < FORMAT_VERSION
            && !crate::READABLE_FORMAT_VERSIONS.contains(&self.format_version)
        {
            return Err(Error::Format(format!(
                "Formatversion {} ist nicht mehr lesbar",
                self.format_version
            )));
        }
        if self.chunk_size == 0 {
            return Err(Error::Format("chunk_size ist 0".into()));
        }
        if self.wrapped_dek.len() != WRAPPED_DEK_LEN {
            return Err(Error::Format(format!(
                "wrapped_dek hat {} Byte, erwartet {}",
                self.wrapped_dek.len(),
                WRAPPED_DEK_LEN
            )));
        }
        let active = self.ranges_active();
        if active.is_empty() && !self.flags.contains(FooterFlags::LOCK_ONLY) {
            return Err(Error::Format("keine aktive Reichweite".into()));
        }
        if active.len() > MAX_RANGES {
            return Err(Error::Format(format!(
                "{} Reichweiten, Maximum {}",
                active.len(),
                MAX_RANGES
            )));
        }
        let mut plain_covered = 0u64;
        let mut expect_ct = 0u64;
        for r in &active {
            // Geprueft, nicht gerechnet — der Fuss ist nicht geschuetzt.
            let reichweite = r
                .plain_off
                .checked_add(r.plain_len)
                .ok_or_else(|| Error::Format("Reichweite hat eine unmoegliche Laenge".into()))?;
            if reichweite > self.plain_size {
                return Err(Error::Format(format!(
                    "Reichweite {}+{} ueberschreitet Klartextgroesse {}",
                    r.plain_off, r.plain_len, self.plain_size
                )));
            }
            if r.ct_off != expect_ct {
                return Err(Error::Format(format!(
                    "Reichweiten-Chiffriertext setzt nicht an {} an (ist {})",
                    expect_ct, r.ct_off
                )));
            }
            expect_ct += r.plain_len;
            plain_covered += r.plain_len;
        }
        // Reichweiten duerfen sich nicht ueberlappen: sonst waere der Restore
        // nicht deterministisch.
        for i in 0..active.len() {
            for j in (i + 1)..active.len() {
                let a = &active[i];
                let b = &active[j];
                if a.plain_off < b.plain_off + b.plain_len
                    && b.plain_off < a.plain_off + a.plain_len
                {
                    return Err(Error::Format("Reichweiten ueberlappen sich".into()));
                }
            }
        }
        let chunks = chunks_for_ranges(&active, self.chunk_size as u64);
        if u64::from(self.n_chunks) != chunks {
            return Err(Error::Format(format!(
                "n_chunks={} passt nicht zu {} Chunks aus den Reichweiten",
                self.n_chunks, chunks
            )));
        }
        if self.tags_len != chunks * (TAG_LEN as u64) {
            return Err(Error::Format(format!(
                "tags_len={} passt nicht zu {} Chunks",
                self.tags_len, chunks
            )));
        }
        if self.ct_total != plain_covered + self.tags_len {
            return Err(Error::Format(format!(
                "ct_total={} passt nicht zu Reichweiten {} + Tags {}",
                self.ct_total, plain_covered, self.tags_len
            )));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut buf = vec![0u8; FOOTER_LEN];
        buf[off::MAGIC..off::MAGIC + 4].copy_from_slice(&FOOTER_MAGIC);
        buf[off::VERSION] = self.format_version;
        buf[off::CIPHER] = self.cipher as u8;
        buf[off::KEX] = self.kex as u8;
        buf[off::FLAGS] = self.flags.bits();
        put_u32(&mut buf, off::CHUNK_SIZE, self.chunk_size);
        let n_active = self.ranges_active().len() as u8;
        buf[off::N_RANGES] = n_active;
        put_u32(&mut buf, off::N_CHUNKS, self.n_chunks);
        buf[off::FILE_ID..off::FILE_ID + FILE_ID_LEN].copy_from_slice(&self.file_id);
        put_u64(&mut buf, off::PLAIN_SIZE, self.plain_size);
        put_u64(&mut buf, off::TAGS_LEN, self.tags_len);
        put_u64(&mut buf, off::CT_TOTAL, self.ct_total);
        for (r, base) in self.ranges.iter().zip(off::RANGE_OFFS.iter()) {
            put_u64(&mut buf, *base, r.plain_off);
            put_u64(&mut buf, *base + 8, r.plain_len);
            put_u64(&mut buf, *base + 16, r.ct_off);
        }
        buf[off::WRAPPED_DEK..off::WRAPPED_DEK + WRAPPED_DEK_LEN]
            .copy_from_slice(&self.wrapped_dek);
        buf[off::NONCE_BASE..off::NONCE_BASE + NONCE_LEN].copy_from_slice(&self.nonce_base);
        buf[off::RANGE_SHA..off::RANGE_SHA + 32].copy_from_slice(&self.range_sha256);
        buf[off::HOST_ID..off::HOST_ID + HOST_ID_LEN].copy_from_slice(&self.host_id);
        buf[off::BUILD_ID..off::BUILD_ID + BUILD_ID_LEN].copy_from_slice(&self.build_id);
        put_u64(&mut buf, off::CREATED, self.created_unix as u64);
        let crc = crc32(&buf[..off::CRC_COVER]);
        put_u32(&mut buf, off::CRC, crc);
        Ok(buf)
    }

    /// Parst einen Footer. `bytes` muss genau FOOTER_LEN Byte lang sein.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != FOOTER_LEN {
            return Err(Error::Format(format!(
                "Footer hat {} Byte, erwartet {}",
                bytes.len(),
                FOOTER_LEN
            )));
        }
        if bytes[off::MAGIC..off::MAGIC + 4] != FOOTER_MAGIC {
            return Err(Error::Format("Footer-Magie fehlt".into()));
        }
        let want = crc32(&bytes[..off::CRC_COVER]);
        let got = read_u32(bytes, off::CRC);
        if want != got {
            return Err(Error::Format(format!(
                "Footer-CRC falsch: erwartet {:08x}, gelesen {:08x}",
                want, got
            )));
        }
        let format_version = bytes[off::VERSION];
        let mut ranges = Self::empty_ranges();
        for (slot, base) in ranges.iter_mut().zip(off::RANGE_OFFS.iter()) {
            *slot = Range {
                plain_off: read_u64(bytes, *base),
                plain_len: read_u64(bytes, *base + 8),
                ct_off: read_u64(bytes, *base + 16),
            };
        }
        let declared = bytes[off::N_RANGES] as usize;
        if declared > MAX_RANGES {
            return Err(Error::Format(format!(
                "n_ranges={} ueber Maximum {}",
                declared, MAX_RANGES
            )));
        }
        for r in &ranges[declared..] {
            if !r.is_empty() {
                return Err(Error::Format(
                    "Reichweite gesetzt, aber von n_ranges nicht eroeffnet".into(),
                ));
            }
        }
        let footer = Footer {
            format_version,
            cipher: CipherId::from_u8(bytes[off::CIPHER])?,
            kex: KexId::from_u8(bytes[off::KEX])?,
            flags: FooterFlags::from(bytes[off::FLAGS]),
            chunk_size: read_u32(bytes, off::CHUNK_SIZE),
            n_chunks: read_u32(bytes, off::N_CHUNKS),
            file_id: array16(&bytes[off::FILE_ID..off::FILE_ID + FILE_ID_LEN]),
            plain_size: read_u64(bytes, off::PLAIN_SIZE),
            tags_len: read_u64(bytes, off::TAGS_LEN),
            ct_total: read_u64(bytes, off::CT_TOTAL),
            ranges,
            wrapped_dek: bytes[off::WRAPPED_DEK..off::WRAPPED_DEK + WRAPPED_DEK_LEN].to_vec(),
            nonce_base: array12(&bytes[off::NONCE_BASE..off::NONCE_BASE + NONCE_LEN]),
            range_sha256: array32(&bytes[off::RANGE_SHA..off::RANGE_SHA + 32]),
            host_id: array16(&bytes[off::HOST_ID..off::HOST_ID + HOST_ID_LEN]),
            build_id: array16(&bytes[off::BUILD_ID..off::BUILD_ID + BUILD_ID_LEN]),
            created_unix: read_u64(bytes, off::CREATED) as i64,
        };
        footer.validate()?;
        Ok(footer)
    }

    pub fn file_id_hex(&self) -> String {
        hex(&self.file_id)
    }
}

fn array16(s: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(s);
    a
}
fn array12(s: &[u8]) -> [u8; 12] {
    let mut a = [0u8; 12];
    a.copy_from_slice(s);
    a
}
fn array32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}
fn read_u64(buf: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Reichweitenplanung: Kopf- und Fussteil einer Datei.
///
/// Regeln:
/// - Dateien unter `min_size` werden nicht angefasst (zurueck: leerer Vektor).
/// - Kopf- und Fussteil duerfen sich nicht ueberlappen; bei kleinen Dateien
///   entsteht eine einzige Reichweite ueber die ganze Datei.
/// - Die Reichweitenplanung ist **alleinige Quelle** fuer die verschluesselte
///   Laenge. Die Dateigroesse wird nie zurueckgerechnet (Risiko R2).
pub fn plan_ranges(plain_size: u64, head_len: u64, tail_len: u64, min_size: u64) -> Vec<Range> {
    if plain_size < min_size || plain_size == 0 {
        return Vec::new();
    }
    let head = head_len.min(plain_size);
    // Fussteil nur, wenn noch Platz neben dem Kopf bleibt.
    if head >= plain_size {
        return vec![Range {
            plain_off: 0,
            plain_len: plain_size,
            ct_off: 0,
        }];
    }
    let tail = tail_len.min(plain_size - head);
    if tail == 0 {
        return vec![Range {
            plain_off: 0,
            plain_len: head,
            ct_off: 0,
        }];
    }
    vec![
        Range {
            plain_off: 0,
            plain_len: head,
            ct_off: 0,
        },
        Range {
            plain_off: plain_size - tail,
            plain_len: tail,
            ct_off: head,
        },
    ]
}

/// Anzahl Chunks ueber alle Reichweiten. Deterministisch, well Resume und
/// Decryptor dieselbe Nummerierung brauchen (B004).
pub(crate) fn chunks_for_ranges(ranges: &[Range], chunk_size: u64) -> u64 {
    if chunk_size == 0 {
        return 0;
    }
    ranges
        .iter()
        .filter(|r| !r.is_empty())
        .map(|r| r.plain_len.div_ceil(chunk_size))
        .sum()
}

/// Nummerierung eines Chunks: globaler Index ueber alle Reichweiten in
/// Reichweitenreihenfolge, dazu der Index innerhalb der Reichweite.
///
/// Die Chunk-Maschinerie ist Maschinbau der Chiffre (`kxenc`) und nicht Teil
/// des oeffentlichen Formatvertrags — sie ist deshalb crate-intern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChunkRef {
    pub range_index: u8,
    pub index_in_range: u64,
    pub global_index: u64,
    pub plain_off: u64,
    pub plain_len: u64,
    pub ct_off: u64,
    pub is_final_global: bool,
}

pub(crate) fn chunk_iter(ranges: &[Range], chunk_size: u64) -> Vec<ChunkRef> {
    let mut out = Vec::new();
    if chunk_size == 0 {
        return out;
    }
    let active: Vec<Range> = ranges.iter().copied().filter(|r| !r.is_empty()).collect();
    let total = chunks_for_ranges(&active, chunk_size);
    let mut global = 0u64;
    for (ri, r) in active.iter().enumerate() {
        let n = r.plain_len.div_ceil(chunk_size);
        for i in 0..n {
            let off = i * chunk_size;
            let len = chunk_size.min(r.plain_len - off);
            out.push(ChunkRef {
                range_index: ri as u8,
                index_in_range: i,
                global_index: global,
                plain_off: r.plain_off + off,
                plain_len: len,
                ct_off: r.ct_off + off,
                is_final_global: global + 1 == total,
            });
            global += 1;
        }
    }
    out
}

/// Nonce-Regel (B004, B006).
///
/// `nonce[0..4]`  = 4 Byte aus der pro Datei zufaelligen Nonce-Basis.
/// `nonce[4..12]` = BE-u64 `(range_index << 32) | index_in_range`.
///
/// Damit ist die Nonce pro (Datei, Reichweite, Chunk) eindeutig und haengt
/// nicht an Uhr oder RAM-Zaehler: ein Resume nach Absturz rechnet die gleiche
/// Folge, weil Reichweiten und Chunkgroessen im Footer stehen. Die Nonce ist
/// ausserdem an die Per-File-DEK gebunden, eine Wiederverwendung ueber Dateien
/// hinweg ist damit wirkungslos.
///
/// **Grenze:** der Index in der Range braucht 32 Bit. Ab `index_in_range >=
/// 2^32` laeuft er in das Bitfeld des Range-Index, und Range 1 ist dann nicht
/// mehr von Range 0 zu unterscheiden. `kxenc::seal` weist solche Reichweiten
/// ab; fuer eine Datei ist die Grenze bei 64-KiB-Chunks erst bei 256 TiB
/// erreicht.
pub(crate) fn nonce_for(
    base: &[u8; NONCE_LEN],
    range_index: u8,
    index_in_range: u64,
) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[0..4].copy_from_slice(&base[0..4]);
    let packed: u64 = ((range_index as u64) << 32) | index_in_range;
    n[4..12].copy_from_slice(&packed.to_be_bytes());
    n
}

/// Domain-Separator fuer die AAD.
pub const AAD_LABEL: &[u8] = b"KXENC-AAD1";

/// Der Kontext eines Chunks fuer die AAD-Berechnung.
///
/// Die Felder gehen in fester Reihenfolge in die AAD ein. Sie liegen in
/// einer Struktur statt in acht Einzelargumenten — die Aufrufstellen
/// bleiben dadurch lesbar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChunkContext<'a> {
    /// Die Formatversion des Containers.
    pub format_version: u8,
    /// Der Index der Range im Container.
    pub range_index: u8,
    /// Der Index des Chunks innerhalb der Range.
    pub index_in_range: u64,
    /// Der Offset des Chunks im Klartextraum.
    ///
    /// Er steht in der AAD, damit ein verschobener Chunk auch dann scheitert,
    /// wenn die Chunk-Nummer gleich bleibt — der Offset ist die dritte
    /// Bindung neben Laenge und Nummer.
    pub plain_off: u64,
    /// Die Laenge des Klartexts dieses Chunks.
    pub plain_len: u64,
    /// Ob der Chunk der letzte des Containers ist.
    pub is_final_global: bool,
    /// Die Datei-Kennung.
    pub file_id: &'a [u8; FILE_ID_LEN],
    /// Die Host-Kennung.
    pub host_id: &'a [u8; HOST_ID_LEN],
}

/// Additional Authenticated Data pro Chunk. Der Chunk-Index sitzt in der AAD,
/// darum schlaegt Umsortieren und Duplizieren von Chunks fehl (B003).
///
/// Das Layout ist fest: `AAD_LABEL || format_version || range_index ||
/// index_in_range(BE u64) || plain_off(BE u64) || plain_len(BE u64) ||
/// is_final_global(1|0) || file_id(16) || host_id(16)`. Es bindet damit
/// **Offset, Laenge und Chunk-Nummer** jedes Chunks.
pub(crate) fn aad_for(out: &mut Vec<u8>, ctx: &ChunkContext<'_>) {
    let ChunkContext {
        format_version,
        range_index,
        index_in_range,
        plain_off,
        plain_len,
        is_final_global,
        file_id,
        host_id,
    } = *ctx;
    out.clear();
    out.extend_from_slice(AAD_LABEL);
    out.push(format_version);
    out.push(range_index);
    out.extend_from_slice(&index_in_range.to_be_bytes());
    out.extend_from_slice(&plain_off.to_be_bytes());
    out.extend_from_slice(&plain_len.to_be_bytes());
    out.push(if is_final_global { 1 } else { 0 });
    out.extend_from_slice(file_id);
    out.extend_from_slice(host_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn footer_stub() -> Footer {
        let ranges = plan_ranges(1_000_000, 64 * 1024, 64 * 1024, 4096);
        let chunk = 1024 * 1024u64;
        let n = chunks_for_ranges(&ranges, chunk);
        let ct_total = ranges.iter().map(|r| r.plain_len).sum::<u64>() + n * (TAG_LEN as u64);
        Footer {
            format_version: FORMAT_VERSION,
            cipher: CipherId::ChaCha20Poly1305Detached,
            kex: KexId::HybridX25519MlKem768,
            flags: FooterFlags::empty(),
            chunk_size: chunk as u32,
            n_chunks: n as u32,
            file_id: [7u8; FILE_ID_LEN],
            plain_size: 1_000_000,
            tags_len: n * (TAG_LEN as u64),
            ct_total,
            ranges: Footer::empty_ranges(),
            wrapped_dek: vec![3u8; WRAPPED_DEK_LEN],
            nonce_base: [9u8; NONCE_LEN],
            range_sha256: [5u8; 32],
            host_id: [1u8; HOST_ID_LEN],
            build_id: [2u8; BUILD_ID_LEN],
            created_unix: 1_762_483_200,
        }
        .with_ranges(ranges)
    }

    impl Footer {
        fn with_ranges(mut self, ranges: Vec<Range>) -> Self {
            for (i, r) in ranges.into_iter().take(MAX_RANGES).enumerate() {
                self.ranges[i] = r;
            }
            self
        }
    }

    #[test]
    fn footer_roundtrip_is_byte_exact() {
        let f = footer_stub();
        let bytes = f.encode().unwrap();
        assert_eq!(bytes.len(), FOOTER_LEN);
        let back = Footer::decode(&bytes).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn footer_crc_catches_single_bit_flip() {
        let mut bytes = footer_stub().encode().unwrap();
        bytes[70] ^= 1;
        let err = Footer::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("CRC"), "err: {err}");
    }

    #[test]
    fn ranges_never_overlap_and_cover_only_head_tail() {
        let r = plan_ranges(1_000_000, 65_536, 65_536, 4096);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].plain_off, 0);
        assert_eq!(r[0].plain_len, 65_536);
        assert_eq!(r[1].plain_off, 1_000_000 - 65_536);
        assert_eq!(r[1].ct_off, 65_536);
        let covered: u64 = r.iter().map(|x| x.plain_len).sum();
        assert!(covered < 1_000_000, "Mittelfeld bleibt unbetroffen");
    }

    #[test]
    fn small_file_collapses_to_single_range() {
        let r = plan_ranges(100, 65_536, 65_536, 1);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].plain_len, 100);
        // Kleiner als Mindestgroesse -> keine Reichweite, Datei bleibt in Ruhe.
        assert!(plan_ranges(10, 65_536, 65_536, 4096).is_empty());
        assert!(plan_ranges(0, 65_536, 65_536, 1).is_empty());
    }

    #[test]
    fn head_plus_tail_bigger_than_file_does_not_double_count() {
        let r = plan_ranges(10_000, 8_000, 8_000, 1);
        let covered: u64 = r.iter().map(|x| x.plain_len).sum();
        assert_eq!(covered, 10_000, "Ueberlappung darf nicht doppelt zaehlen");
        for pair in r.windows(2) {
            assert!(
                pair[0].plain_off + pair[0].plain_len <= pair[1].plain_off,
                "Ueberlappung: {pair:?}"
            );
        }
    }

    #[test]
    fn chunk_numbering_is_dense_and_stable() {
        let r = plan_ranges(1_000_000, 65_536, 65_536, 4096);
        let chunks = chunk_iter(&r, 16 * 1024);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.global_index, i as u64);
        }
        assert!(chunks.last().unwrap().is_final_global);
        let total = chunks_for_ranges(&r, 16 * 1024) as usize;
        assert_eq!(chunks.len(), total);
        // Resume nach Absturz muss dieselbe Nummerierung liefern.
        assert_eq!(
            chunk_iter(&plan_ranges(1_000_000, 65_536, 65_536, 4096), 16 * 1024),
            chunks
        );
    }

    #[test]
    fn nonce_is_unique_per_chunk_and_resume_stable() {
        let base = [0x11u8; NONCE_LEN];
        let mut seen = std::collections::HashSet::new();
        for r in 0..2u8 {
            for i in 0..5000u64 {
                let n = nonce_for(&base, r, i);
                assert!(seen.insert(n), "Nonce-Kollision r{r} i{i}");
            }
        }
        assert_eq!(nonce_for(&base, 1, 42), nonce_for(&base, 1, 42));
        assert_ne!(nonce_for(&base, 0, 42), nonce_for(&base, 1, 42));
        assert_ne!(nonce_for(&base, 0, 42), nonce_for(&base, 0, 43));
    }

    /// Der Chunk-Kontext der AAD-Tests.
    fn chunk_ctx<'a>(
        index_in_range: u64,
        file_id: &'a [u8; FILE_ID_LEN],
        host_id: &'a [u8; HOST_ID_LEN],
    ) -> ChunkContext<'a> {
        ChunkContext {
            format_version: 1,
            range_index: 0,
            index_in_range,
            plain_off: index_in_range * 1024,
            plain_len: 1024,
            is_final_global: false,
            file_id,
            host_id,
        }
    }

    #[test]
    fn aad_binds_index_and_file() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        aad_for(&mut a, &chunk_ctx(3, &[0u8; 16], &[0u8; 16]));
        aad_for(&mut b, &chunk_ctx(4, &[0u8; 16], &[0u8; 16]));
        assert_ne!(a, b, "Chunk-Index muss in der AAD stehen");
        aad_for(&mut b, &chunk_ctx(3, &[1u8; 16], &[0u8; 16]));
        assert_ne!(a, b, "file_id muss gebunden sein");
        aad_for(&mut b, &chunk_ctx(3, &[0u8; 16], &[9u8; 16]));
        assert_ne!(a, b, "host_id muss gebunden sein");
    }

    #[test]
    fn aad_binds_und_laenge_und_offset() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        aad_for(&mut a, &chunk_ctx(3, &[0u8; 16], &[0u8; 16]));
        // Gleiche Nummer, gleiche Laenge — aber ein anderer Offset.
        let mut c = chunk_ctx(3, &[0u8; 16], &[0u8; 16]);
        c.plain_off += 512;
        aad_for(&mut b, &c);
        assert_ne!(a, b, "der Offset muss in der AAD stehen");
        // Gleiche Nummer und Offset, aber eine andere Laenge.
        let mut d = chunk_ctx(3, &[0u8; 16], &[0u8; 16]);
        d.plain_len = 2048;
        aad_for(&mut b, &d);
        assert_ne!(a, b, "die Laenge muss in der AAD stehen");
    }

    #[test]
    fn validate_rejects_inconsistencies() {
        let mut f = footer_stub();
        f.tags_len += 16;
        assert!(f.validate().is_err(), "tags_len muss zu n_chunks passen");

        let mut f = footer_stub();
        f.ranges[1].plain_off += 1;
        assert!(
            f.validate().is_err(),
            "ct_off muss an der Reichweite haengen"
        );

        let mut f = footer_stub();
        f.ranges[1] = Range {
            plain_off: 10,
            plain_len: 500_000,
            ct_off: 65_536,
        };
        assert!(f.validate().is_err(), "Ueberlappung muss abgewiesen werden");

        let mut f = footer_stub();
        f.format_version = FORMAT_VERSION + 7;
        assert!(
            f.validate().is_err(),
            "unbekannte Formatversion muss abgewiesen werden"
        );

        let mut f = footer_stub();
        f.wrapped_dek.pop();
        assert!(f.validate().is_err(), "wrapped_dek-Laenge ist fest");
    }

    #[test]
    fn chunk_size_zero_never_divides_by_zero() {
        let r = plan_ranges(1000, 100, 100, 1);
        assert_eq!(chunks_for_ranges(&r, 0), 0);
        assert!(chunk_iter(&r, 0).is_empty());
    }
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
///
/// Die Pruefsumme des Fusses ist ein Reissverschluss, kein Siegel: sie
/// merkt einzelne Bitfehler, aber keine gezielte Manipulation. Davor schuetzt
/// der umschlossene DEK (`kxenc`), dessen AAD die Fussfelder bindet.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for b in bytes {
        c = CRC_TABLE[((c ^ (*b as u32)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod crc_tests {
    use super::crc32;

    #[test]
    fn crc32_matches_known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }
}
