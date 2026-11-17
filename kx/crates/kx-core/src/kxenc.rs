//! Die Chiffre des KXENC-Containers.
//!
//! `format.rs` beschreibt das Layout — es verschluesselt nichts. Hier sitzt
//! die Chiffre: Chunk → AAD → AEAD → Ciphertext-Offset. Ein eigenes Modul,
//! weil `format.rs` dadurch nicht waechst, sondern schrumpft: die doppelte
//! `KexId` (sie liegt seit dem Umbau in `kex.rs`) wird entfernt, und die
//! Chunk-Maschinerie wird crate-intern.
//!
//! # Was der Container enthaelt
//!
//! ```text
//! 0                chunk ciphertext            (in Place, gleiche Laenge wie Klartext)
//! P                tags, 16 Byte je Chunk     (append, detached)
//! P + tags_len     footer, 320 Byte, Klartext (append)
//! ```
//!
//! `seal` verschluesselt seinen ganzen Puffer als **eine** Reichweite. Die
//! Kopf-/Fussteil-Planung aus `format::plan_ranges` (zwei Reichweiten, mittleres
//! Feld unberuehrt) ist der dateiweisen Engine vorbehalten — sie braucht eine
//! Datei, keinen Puffer.
//!
//! Der Chiffriertext liegt **an der Stelle des Klartexts** (gleicher Offset,
//! gleiche Laenge). `ct_off` in der Fusszeile beschreibt dagegen den
//! logischen Chiffriertextstrom — die Reichweiten aneinandergeklebt. Fuer die
//! Position im Container ist `plain_off` zustaendig; bei einer einzigen
//! Reichweite fallen beide zusammen.
//!
//! # Der Schluesselweg
//!
//! - Je Container ein **frischer DEK** (32 Byte). Die Chunks werden mit ihm
//!   verschluesselt.
//! - Der DEK wird mit dem **Master-Key des Hosts** umschlossen und liegt als
//!   `wrapped_dek` im Fuss: `Nonce (12) || Chiffriertext (DEK 32 || Nonce-Basis
//!   12) || Tag (16)`. Es gibt keinen zweiten Schluesselkanal — wer den
//!   Master-Key hat, oeffnet den Container.
//! - Die Nonce-Basis steht zusaetzlich im Fuss. Sie wird beim Entschluesseln
//!   gegen die Basis aus dem umschlossenen DEK geprueft: die beiden muessen
//!   uebereinstimmen.
//!
//! # Was die AAD bindet
//!
//! Jeder Chunk traegt seinen **Offset**, seine **Laenge**, seine **Chunk-Nummer**
//! (Range-Index und Index in der Range), das Datei- und das Host-Feld sowie das
//! Flag „letzter Chunk". Ein verschobener, gekuerzter oder vertauschter Chunk
//! scheitert deshalb am AEAD, nicht erst an einer Laengenpruefung.
//!
//! # Annahmen, die der Maintainer pruefen sollte
//!
//! - `host_id` und `build_id` stehen als Null im Fuss. Der Container kennt den
//!   Host nicht — die Hostbindung laeuft ueber den umschlossenen DEK. Wer die
//!   echte Host-Kennung eintragen will, muss die AAD mitziehen.
//! - Ein Container **ohne Inhalt** traegt das Flag `LOCK_ONLY`, weil
//!   `Footer::validate` mindestens eine aktive Reichweite verlangt.
//! - Die Nonce-Ableitung packt `range_index << 32 | index_in_range` in acht
//!   Byte. Sie ist damit eindeutig, solange der Index in der Range kleiner als
//!   2^32 ist — `seal` und `open` weisen groessere Reichweiten ab.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{
    aad_for, chunk_iter, nonce_for, plan_ranges, ChunkContext, CipherId, Footer, FooterFlags,
    Range, BUILD_ID_LEN, DEK_LEN, FILE_ID_LEN, FOOTER_LEN, HOST_ID_LEN, NONCE_LEN, TAG_LEN,
    WRAPPED_DEK_LEN,
};
use crate::kex::KexId;
use crate::FORMAT_VERSION;

/// Die Chunk-Groesse, mit der `seal` arbeitet. Der Fuss nennt sie, damit ein
/// Leser die Chunks findet, ohne zu raten.
pub const CHUNK_SIZE: u32 = 64 * 1024;

/// Der Info-String der Schluesselableitung fuer das Umschliessen des DEK —
/// Teil des Formats.
const DEK_INFO: &[u8] = b"kx/kxenc/dek/v1";

/// Der Salt der Schluesselableitung fuer das Umschliessen des DEK — Teil des
/// Formats.
const DEK_SALT: &[u8] = b"kx-kxenc-dek-salt-v1";

/// Die AAD des DEK-Wrappings. Sie bindet die Datei-Kennung, die Reichweiten
/// und die Groessen des Containers an den umschlossenen DEK: ein umgebauter
/// Fuss scheitert am AEAD, nicht erst an der CRC.
const DEK_AAD_LABEL: &[u8] = b"KXENC-DEK1";

/// Die maximale Zahl Chunks je Reichweite. Die Nonce-Ableitung braucht 32 Bit
/// fuer den Index in der Range — darueber hinaus waere die Nonce nicht mehr
/// eindeutig.
const MAX_CHUNKS_PER_RANGE: u64 = 1 << 32;

/// Verschluesselt die Bytes in einen KXENC-Container.
///
/// Der DEK ist ein frischer Schluessel je Container; umschlossen mit dem
/// Master-Key des Hosts und im Fuss abgelegt.
pub fn seal(klartext: &[u8], master_key: &[u8], kex: KexId) -> Result<Vec<u8>> {
    if master_key.is_empty() {
        return Err(Error::Crypto("KXENC ohne Master-Key".into()));
    }

    let plain_size = klartext.len() as u64;
    let chunk_size = u64::from(CHUNK_SIZE);

    // Eine einzige Reichweite ueber den ganzen Puffer. Fuer einen leeren
    // Puffer gibt es keine Reichweite — der Fuss traegt dann LOCK_ONLY.
    let ranges = if plain_size == 0 {
        Vec::new()
    } else {
        plan_ranges(plain_size, plain_size, 0, 0)
    };

    for r in &ranges {
        let chunks = r.plain_len.div_ceil(chunk_size);
        if chunks > MAX_CHUNKS_PER_RANGE {
            return Err(Error::Format(format!(
                "Reichweite mit {} Chunks ueber der Nonce-Grenze {}",
                chunks, MAX_CHUNKS_PER_RANGE
            )));
        }
    }
    let chunks = chunk_iter(&ranges, chunk_size);
    if chunks.len() > u32::MAX as usize {
        return Err(Error::Format(format!(
            "{} Chunks passen nicht in die Fusszeile",
            chunks.len()
        )));
    }

    // Der DEK: frisch je Container, im Speicher genullt.
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(&mut dek[..]);

    // Die Nonce-Basis: pro Container zufaellig, im Fuss lesbar.
    let mut nonce_base = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_base);

    // Die Datei-Kennung: pro Container zufaellig, bindet die Chunks.
    let mut file_id = [0u8; FILE_ID_LEN];
    OsRng.fill_bytes(&mut file_id);

    // Der Container kennt den Host nicht — die Hostbindung laeuft ueber den
    // umschlossenen DEK. Die Felder stehen als Null im Fuss.
    let host_id = [0u8; HOST_ID_LEN];
    let build_id = [0u8; BUILD_ID_LEN];

    let range_bytes = range_table_bytes(&ranges);
    let range_sha256 = sha256_32(&range_bytes);

    // Der umschlossene DEK.
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    crate::hostkey::hkdf_into(master_key, DEK_SALT, DEK_INFO, &mut wrap_key[..])?;
    let dek_aad = dek_aad(&file_id, &range_bytes, plain_size, chunk_size);
    let mut wrap_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut wrap_nonce);
    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key[..]));
    let mut wrap_plain = Zeroizing::new(Vec::with_capacity(DEK_LEN + NONCE_LEN));
    wrap_plain.extend_from_slice(&dek[..]);
    wrap_plain.extend_from_slice(&nonce_base);
    let wrapped = wrap_cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: &wrap_plain,
                aad: &dek_aad,
            },
        )
        .map_err(|_| Error::Crypto("KXENC-DEK-Umschliessung fehlgeschlagen".into()))?;
    // Der Chiffriertext traegt DEK und Nonce-Basis, das Tag steht dahinter.
    let mut wrapped_dek = Vec::with_capacity(WRAPPED_DEK_LEN);
    wrapped_dek.extend_from_slice(&wrap_nonce);
    wrapped_dek.extend_from_slice(&wrapped[..DEK_LEN + NONCE_LEN]);
    wrapped_dek.extend_from_slice(&wrapped[DEK_LEN + NONCE_LEN..]);

    // Die Chunks: AAD, Nonce, AEAD. Der Chiffriertext ersetzt den Klartext an
    // seiner Stelle, das Tag wandert in den Anhang.
    let mut content = klartext.to_vec();
    let mut tags = vec![0u8; chunks.len() * TAG_LEN];
    let mut aad = Vec::new();
    let chunk_cipher = ChaCha20Poly1305::new(Key::from_slice(&dek[..]));
    for ch in &chunks {
        let ctx = ChunkContext {
            format_version: FORMAT_VERSION,
            range_index: ch.range_index,
            index_in_range: ch.index_in_range,
            plain_off: ch.plain_off,
            plain_len: ch.plain_len,
            is_final_global: ch.is_final_global,
            file_id: &file_id,
            host_id: &host_id,
        };
        aad_for(&mut aad, &ctx);
        let nonce = nonce_for(&nonce_base, ch.range_index, ch.index_in_range);
        let start = ch.plain_off as usize;
        let ende = start + ch.plain_len as usize;
        let sealed = chunk_cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &klartext[start..ende],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("KXENC-Chunk-Verschluesselung fehlgeschlagen".into()))?;
        content[start..ende].copy_from_slice(&sealed[..ch.plain_len as usize]);
        let tag_at = ch.global_index as usize * TAG_LEN;
        tags[tag_at..tag_at + TAG_LEN].copy_from_slice(&sealed[ch.plain_len as usize..]);
    }

    // Der Fuss.
    let mut flags = FooterFlags::empty();
    if plain_size == 0 {
        // Ohne Inhalt gibt es keine aktive Reichweite — die Pruefung des Fusses
        // verlangt dann das LOCK_ONLY-Flag.
        flags.insert(FooterFlags::LOCK_ONLY);
    }
    let mut footer_ranges = Footer::empty_ranges();
    for (slot, r) in footer_ranges.iter_mut().zip(ranges.iter()) {
        *slot = *r;
    }
    let plain_covered: u64 = ranges.iter().map(|r| r.plain_len).sum();
    let footer = Footer {
        format_version: FORMAT_VERSION,
        cipher: CipherId::ChaCha20Poly1305Detached,
        kex,
        flags,
        chunk_size: CHUNK_SIZE,
        n_chunks: chunks.len() as u32,
        file_id,
        plain_size,
        tags_len: tags.len() as u64,
        ct_total: plain_covered + tags.len() as u64,
        ranges: footer_ranges,
        wrapped_dek,
        nonce_base,
        range_sha256,
        host_id,
        build_id,
        created_unix: now_unix(),
    };
    let footer_bytes = footer.encode()?;

    let mut container = Vec::with_capacity(content.len() + tags.len() + footer_bytes.len());
    container.extend_from_slice(&content);
    container.extend_from_slice(&tags);
    container.extend_from_slice(&footer_bytes);
    Ok(container)
}

/// Oeffnet einen KXENC-Container. Prueft Laenge, Fusszeile, AAD und Schluessel.
pub fn open(container: &[u8], master_key: &[u8]) -> Result<Vec<u8>> {
    if master_key.is_empty() {
        return Err(Error::Crypto("KXENC ohne Master-Key".into()));
    }
    if container.len() < FOOTER_LEN {
        return Err(Error::Format(format!(
            "Container hat {} Byte, mindestens {} (Fusszeile) noetig",
            container.len(),
            FOOTER_LEN
        )));
    }

    // Der Fuss steht am Ende und ist ohne Schluessel lesbar.
    let footer = Footer::decode(&container[container.len() - FOOTER_LEN..])?;

    // Die Flags sind eine Zusage ueber den Container: LOCK_ONLY heisst "leer",
    // PARTIAL heisst "unvollstaendig". Beides darf keinen Klartext liefern.
    if footer.flags.contains(FooterFlags::LOCK_ONLY) && footer.plain_size > 0 {
        return Err(Error::Format(
            "LOCK_ONLY auf einem Container mit Inhalt".into(),
        ));
    }
    if footer.flags.contains(FooterFlags::PARTIAL) {
        return Err(Error::Format(
            "PARTIAL — der Container ist unvollstaendig".into(),
        ));
    }
    // Geprueft, nicht gerechnet: ein Angreifer setzt `plain_size` auf
    // u64::MAX und rechnet die CRC neu — die ist nicht geschuetzt.
    let erwartet = footer
        .plain_size
        .checked_add(footer.tags_len)
        .and_then(|s| s.checked_add(FOOTER_LEN as u64))
        .ok_or_else(|| Error::Format("Fuss beschreibt eine unmoegliche Laenge".into()))?;
    if erwartet != container.len() as u64 {
        return Err(Error::Format(format!(
            "Container hat {} Byte, der Fuss beschreibt {}",
            container.len(),
            erwartet
        )));
    }
    // Erst nach der Laengenpruefung: die Werte passen damit in einen `usize`.
    let plain_size = footer.plain_size as usize;
    let tags_len = footer.tags_len as usize;

    // Der DEK: erst die AAD aus dem Fuss, dann das AEAD.
    let active = footer.ranges_active();
    let range_bytes = range_table_bytes(&active);
    if sha256_32(&range_bytes) != footer.range_sha256 {
        return Err(Error::Format(
            "Pruefsumme der Reichweiten stimmt nicht".into(),
        ));
    }
    let chunk_size = u64::from(footer.chunk_size);
    let dek_aad = dek_aad(&footer.file_id, &range_bytes, footer.plain_size, chunk_size);
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    crate::hostkey::hkdf_into(master_key, DEK_SALT, DEK_INFO, &mut wrap_key[..])?;
    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key[..]));
    let mut sealed = Vec::with_capacity(DEK_LEN + NONCE_LEN + TAG_LEN);
    sealed.extend_from_slice(&footer.wrapped_dek[NONCE_LEN..NONCE_LEN + DEK_LEN + NONCE_LEN]);
    sealed.extend_from_slice(&footer.wrapped_dek[NONCE_LEN + DEK_LEN + NONCE_LEN..]);
    let mut entpackt = Zeroizing::new(Vec::with_capacity(DEK_LEN + NONCE_LEN));
    entpackt.extend_from_slice(
        &wrap_cipher
            .decrypt(
                Nonce::from_slice(&footer.wrapped_dek[..NONCE_LEN]),
                Payload {
                    msg: &sealed,
                    aad: &dek_aad,
                },
            )
            .map_err(|_| Error::Crypto("KXENC-DEK-Entsiegelung fehlgeschlagen".into()))?,
    );
    if entpackt.len() != DEK_LEN + NONCE_LEN {
        return Err(Error::Crypto("KXENC-DEK hat die falsche Laenge".into()));
    }
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    dek.copy_from_slice(&entpackt[..DEK_LEN]);
    let nonce_base = &entpackt[DEK_LEN..];
    if nonce_base != footer.nonce_base.as_slice() {
        return Err(Error::Format(
            "Nonce-Basis im Fuss passt nicht zum umschlossenen DEK".into(),
        ));
    }

    // Die Chunks: an ihrer Stelle entschluesseln, die Tags aus dem Anhang.
    let chunks = chunk_iter(&active, chunk_size);
    let mut content = container[..plain_size].to_vec();
    let tags = &container[plain_size..plain_size + tags_len];
    let mut aad = Vec::new();
    let chunk_cipher = ChaCha20Poly1305::new(Key::from_slice(&dek[..]));
    for ch in &chunks {
        let ctx = ChunkContext {
            format_version: footer.format_version,
            range_index: ch.range_index,
            index_in_range: ch.index_in_range,
            plain_off: ch.plain_off,
            plain_len: ch.plain_len,
            is_final_global: ch.is_final_global,
            file_id: &footer.file_id,
            host_id: &footer.host_id,
        };
        aad_for(&mut aad, &ctx);
        let nonce = nonce_for(&footer.nonce_base, ch.range_index, ch.index_in_range);
        let start = ch.plain_off as usize;
        let ende = start + ch.plain_len as usize;
        let mut chunk_sealed = Vec::with_capacity(ch.plain_len as usize + TAG_LEN);
        chunk_sealed.extend_from_slice(&container[start..ende]);
        let tag_at = ch.global_index as usize * TAG_LEN;
        chunk_sealed.extend_from_slice(&tags[tag_at..tag_at + TAG_LEN]);
        let plaintext = chunk_cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &chunk_sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                Error::Crypto(format!(
                    "KXENC-Chunk {} nicht entschluesselbar",
                    ch.global_index
                ))
            })?;
        content[start..ende].copy_from_slice(&plaintext);
    }
    Ok(content)
}

/// Die Reichweiten als Bytes — Grundlage der Pruefsumme im Fuss und der AAD
/// des DEK-Wrappings.
fn range_table_bytes(ranges: &[Range]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ranges.len() * 24);
    for r in ranges {
        out.extend_from_slice(&r.plain_off.to_le_bytes());
        out.extend_from_slice(&r.plain_len.to_le_bytes());
        out.extend_from_slice(&r.ct_off.to_le_bytes());
    }
    out
}

/// Die AAD des DEK-Wrappings: Datei-Kennung, Reichweiten und Groessen.
fn dek_aad(
    file_id: &[u8; FILE_ID_LEN],
    range_bytes: &[u8],
    plain_size: u64,
    chunk_size: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEK_AAD_LABEL.len() + FILE_ID_LEN + range_bytes.len() + 16);
    aad.extend_from_slice(DEK_AAD_LABEL);
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(range_bytes);
    aad.extend_from_slice(&plain_size.to_le_bytes());
    aad.extend_from_slice(&chunk_size.to_le_bytes());
    aad
}

/// SHA-256 ueber Bytes, als 32 Byte.
fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Die Zeit in Sekunden seit der Unix-Epoche. Ohne Uhr reicht eine 0 — das
/// Feld ist ein Hinweis, kein Sicherheitsmerkmal.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::FOOTER_LEN;

    /// Der Master-Key eines Hosts — 32 Byte, wie `hostkey` sie liefert.
    fn master() -> [u8; 32] {
        [0x5au8; 32]
    }

    /// Ein deutlich erkennbares Muster. Der Test "kein Klartext im Container"
    /// sucht genau diese Zeichenfolge.
    fn muster(laenge: usize) -> Vec<u8> {
        const MUSTER: &[u8] = b"KXENC-KLAR-TEXT-0123456789-ABCDEF";
        let mut out = Vec::with_capacity(laenge);
        while out.len() < laenge {
            let n = (laenge - out.len()).min(MUSTER.len());
            out.extend_from_slice(&MUSTER[..n]);
        }
        out
    }

    /// Der Anteil der Chunks im Container — der Klartextteil des Puffers.
    fn inhalt(container: &[u8]) -> &[u8] {
        let footer =
            Footer::decode(&container[container.len() - FOOTER_LEN..]).expect("Fusszeile lesbar");
        &container[..footer.plain_size as usize]
    }

    #[test]
    fn der_roundtrip_liefert_den_klartext_zurueck() {
        let chunk = CHUNK_SIZE as usize;
        let groessen = [0usize, 1, 100, chunk - 1, chunk, chunk + 1, chunk * 3 + 17];
        for laenge in groessen {
            let klartext = muster(laenge);
            let container =
                seal(&klartext, &master(), KexId::HybridX25519MlKem768).expect("Versiegelung");
            let zurueck = open(&container, &master()).expect("Entschlüsselung");
            assert_eq!(zurueck, klartext, "Laenge {laenge}");
        }
    }

    #[test]
    fn der_container_traegt_die_vereinbarte_laenge() {
        let klartext = muster(CHUNK_SIZE as usize * 2 + 5);
        let container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");
        let footer = Footer::decode(&container[container.len() - FOOTER_LEN..]).expect("Fuss");
        let erwartet = klartext.len() as u64 + footer.tags_len + FOOTER_LEN as u64;
        assert_eq!(container.len() as u64, erwartet);
        assert_eq!(footer.n_chunks, 3);
        assert_eq!(footer.tags_len, 3 * TAG_LEN as u64);
        assert_eq!(footer.plain_size, klartext.len() as u64);
        assert_eq!(footer.chunk_size, CHUNK_SIZE);
    }

    #[test]
    fn ein_falscher_master_key_scheitert() {
        let container =
            seal(&muster(500), &master(), KexId::HybridX25519MlKem768).expect("Versiegelung");

        let ergebnis = open(&container, &[0x11u8; 32]);

        assert!(
            ergebnis.is_err(),
            "ein fremder Master-Key darf nicht oeffnen"
        );
    }

    #[test]
    fn ohne_master_key_ist_weder_versiegeln_noch_oeffnen_moeglich() {
        assert!(seal(&muster(10), &[], KexId::X25519).is_err());
        assert!(open(&muster(10), &[]).is_err());
    }

    #[test]
    fn ein_manipuliertes_byte_im_chiffriertext_scheitert() {
        let klartext = muster(1000);
        let mut container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");
        // In der Mitte des Chiffriertexts kippen.
        container[500] ^= 0x01;

        assert!(
            open(&container, &master()).is_err(),
            "das AEAD muss anschlagen"
        );
    }

    #[test]
    fn ein_manipuliertes_tag_scheitert() {
        let klartext = muster(1000);
        let mut container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");
        let footer = Footer::decode(&container[container.len() - FOOTER_LEN..]).expect("Fuss");
        // Das erste Tag liegt direkt hinter dem Inhalt.
        let tag_at = footer.plain_size as usize;
        container[tag_at] ^= 0x01;

        assert!(open(&container, &master()).is_err());
    }

    #[test]
    fn ein_verschobener_chunk_scheitert() {
        let chunk = CHUNK_SIZE as usize;
        let klartext = muster(chunk * 2);
        let mut container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");
        // Die beiden Chunks tauschen ihre Plaetze: die AAD bindet den Offset
        // und die Chunk-Nummer, also darf das nicht mehr aufgehen.
        let (links, rechts) = container[..chunk * 2].split_at_mut(chunk);
        links.swap_with_slice(rechts);

        assert!(open(&container, &master()).is_err());
    }

    #[test]
    fn ein_abgeschnittener_container_scheitert() {
        let container = seal(&muster(1000), &master(), KexId::X25519).expect("Versiegelung");

        let abgeschnitten = &container[..container.len() - 10];

        assert!(open(abgeschnitten, &master()).is_err());
    }

    #[test]
    fn eine_kaputte_fusszeile_scheitert() {
        let mut container = seal(&muster(1000), &master(), KexId::X25519).expect("Versiegelung");
        let magic_at = container.len() - FOOTER_LEN;
        container[magic_at] = b'X';

        assert!(open(&container, &master()).is_err());
    }

    #[test]
    fn eine_veraenderte_reichweite_scheitert() {
        let mut container = seal(&muster(1000), &master(), KexId::X25519).expect("Versiegelung");
        // Der Offset der ersten Range im Fuss — die CRC schlaegt an, und
        // zusaetzlich der umschlossene DEK.
        let range_at = container.len() - FOOTER_LEN + 60;
        container[range_at] ^= 0x01;

        assert!(open(&container, &master()).is_err());
    }

    #[test]
    fn der_klartext_steht_nicht_im_container() {
        let klartext = muster(1024);
        let container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");

        assert!(
            !container
                .windows(28)
                .any(|fenster| fenster == b"KXENC-KLAR-TEXT-0123456789-ABCDEF"),
            "der Klartext darf im Container nicht auftauchen"
        );
    }

    #[test]
    fn der_klartext_steht_auch_im_inhaltsteil_nicht() {
        let klartext = muster(1024);
        let container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");

        assert!(!inhalt(&container).windows(8).any(|f| f == b"KXENC-KLA"));
    }

    #[test]
    fn zwei_container_derselben_ngabe_unterscheiden_sich() {
        let klartext = muster(1000);
        let a = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");
        let b = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");

        assert_ne!(a, b, "DEK und Nonce-Basis muessen je Container frisch sein");
    }

    #[test]
    fn die_nonce_ist_je_chunk_eindeutig() {
        let base = [0x11u8; NONCE_LEN];
        let mut gesehen = std::collections::HashSet::new();
        for r in 0..2u8 {
            for i in 0..10_000u64 {
                assert!(
                    gesehen.insert(nonce_for(&base, r, i)),
                    "Nonce-Kollision bei Range {r} Index {i}"
                );
            }
        }
        // Die Grenze der Ableitung: der Index in der Range braucht 32 Bit.
        // Darueber waere Range 1 nicht mehr von Range 0 zu unterscheiden —
        // deshalb weist `seal` so grosse Reichweiten ab.
        assert_eq!(nonce_for(&base, 1, 0), nonce_for(&base, 0, 1 << 32));
    }

    #[test]
    fn die_chunks_eines_containers_haben_unterschiedliche_nonces() {
        let klartext = muster(CHUNK_SIZE as usize * 3);
        let container = seal(&klartext, &master(), KexId::X25519).expect("Versiegelung");
        let footer = Footer::decode(&container[container.len() - FOOTER_LEN..]).expect("Fuss");
        let chunks = chunk_iter(&footer.ranges_active(), u64::from(footer.chunk_size));

        let mut gesehen = std::collections::HashSet::new();
        for ch in &chunks {
            let n = nonce_for(&footer.nonce_base, ch.range_index, ch.index_in_range);
            assert!(gesehen.insert(n), "Nonce {ch:?} wiederholt sich");
        }
        assert_eq!(gesehen.len(), chunks.len());
    }

    #[test]
    fn ein_leerer_container_ist_leer_und_oeffenbar() {
        let container = seal(&[], &master(), KexId::X25519).expect("Versiegelung");
        let footer = Footer::decode(&container[container.len() - FOOTER_LEN..]).expect("Fuss");

        assert!(footer.flags.contains(FooterFlags::LOCK_ONLY));
        assert_eq!(footer.plain_size, 0);
        assert_eq!(footer.n_chunks, 0);
        assert!(open(&container, &master())
            .expect("Entschlüsselung")
            .is_empty());
    }

    #[test]
    fn der_umschlossene_dek_traegt_die_nonce_basis() {
        let container = seal(&muster(100), &master(), KexId::X25519).expect("Versiegelung");
        let footer = Footer::decode(&container[container.len() - FOOTER_LEN..]).expect("Fuss");

        assert_eq!(footer.wrapped_dek.len(), WRAPPED_DEK_LEN);
        // Nonce (12) || Chiffriertext (DEK 32 || Basis 12) || Tag (16)
        assert_eq!(
            footer.wrapped_dek.len(),
            NONCE_LEN + DEK_LEN + NONCE_LEN + TAG_LEN
        );
    }
}
