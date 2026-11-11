# kx-tls/src

## Overview
Dieses Verzeichnis enthält die einzige Quelldatei des Crates, `src/lib.rs`, und ist
damit das Crate-Root-Modul: alle öffentlichen Symbole des Crates `kx-tls` werden hier
deklariert und über das Manifest [../Cargo.toml](../Cargo.toml) als `lib`-Target
exportiert. Die Datei enthält keine Tests und keine Submodule.

Der Modulkommentar beschreibt „Server- und Client-TLS-Configuration mit selbstsignierten
Zertifikaten (rcgen) sowie PEM-Datei-Handling für bestehende Zertifikatspfade". Der
PEM-Teil dieser Beschreibung trifft jedoch nicht zu: Beide Funktionen arbeiten
ausschließlich auf PEM-**Bytes**, es findet keinerlei Datei-I/O statt. Die
Dateipfade-Lesart ist durch die Signaturen der öffentlichen API widerlegt
[lib.rs:client_config_trusting].

Die Implementierung stützt sich vollständig auf die Drittanbieter-Crates `rcgen`
(Zertifikatserzeugung), `rustls` (Konfiguration), `rustls-pemfile` (PEM-Parsing),
`rustls-pki-types` (DER-Typen) und `time` (Gültigkeitsdatum); `kx-core` ist im
Manifest deklariert, wird aber nicht importiert.

## Interface
- `pub enum TlsError` — `#[derive(Debug, Error)]` (thiserror), drei Tuple-Varianten mit
  `String`-Payload: `CertGen(String)`, `PemLoad(String)`, `Config(String)`; implementiert
  `std::error::Error`, ohne `Clone`/`PartialEq`/`#[non_exhaustive]` [lib.rs:TlsError]
- `pub struct ServerTls` — ohne Derives; drei öffentliche Felder: `config: Arc<ServerConfig>`,
  `cert_pem: Vec<u8>`, `key_pem: Vec<u8>` [lib.rs:ServerTls]
- `pub fn generate_server_tls(cn: &str) -> Result<ServerTls, TlsError>` — erzeugt
  Zertifikat und Schlüssel, baut die rustls-Server-Config und liefert PEM- und
  DER-Formen nebeneinander [lib.rs:generate_server_tls]
- `pub fn client_config_trusting(cert_pem: &[u8]) -> Result<Arc<ClientConfig>, TlsError>`
  — parst PEM-Bytes zu Zertifikaten, fügt sie in einen leeren `RootCertStore` ein und
  liefert eine `ClientConfig` ohne Client-Authentifizierung [lib.rs:client_config_trusting]
- `pub fn install_crypto_provider()` — installiert den rustls-`ring`-Provider als
  prozessweiten Default. Wird von beiden Builder-Pfaden aufgerufen; ein zweiter
  Aufruf ist unschädlich [lib.rs:install_crypto_provider]

Aufrufkette des Server-Pfads:
`CertificateParams::new` → `params.not_after` setzen → `KeyPair::generate` →
`params.self_signed(&key_pair)` → `cert.pem()` / `key_pair.serialize_pem()` →
`CertificateDer::from` / `PrivateKeyDer::Pkcs8` → `ServerConfig::builder()
.with_no_client_auth().with_single_cert(...)` [lib.rs:generate_server_tls]

Aufrufkette des Client-Pfads:
`install_crypto_provider()` → `RootCertStore::empty()` → `rustls_pemfile::certs` über
`BufReader<Cursor<..>>` → `root_store.add` je Zertifikat →
`ClientConfig::builder().with_root_certificates(...).with_no_client_auth()`
[lib.rs:client_config_trusting]

## Invariants
- `install_crypto_provider()` läuft vor jedem `builder()`-Aufruf. Ohne die
  explizite Installation löst rustls den Provider beim ersten Builder auf, und
  eine mehrdeutige Auflösung ist ein `panic!` — kein `Result`, den man abfangen
  könnte [lib.rs:install_crypto_provider] [lib.rs:generate_server_tls]
  [lib.rs:client_config_trusting]
- `install_crypto_provider()` ist idempotent: `install_default()` liefert beim
  zweiten Aufruf einen Fehler, der ignoriert wird — der erste installierte
  Provider bleibt [lib.rs:install_crypto_provider]
- Der `cn`-Parameter wird ausschließlich als Subject-Alternative-Name verwendet
  (`CertificateParams::new(vec![cn.to_string()])`); der Subject-DN bleibt beim
  rcgen-Default ("rcgen self signed cert"), der Subject-CN ist also *nicht* der
  übergebene Wert [lib.rs:generate_server_tls]
- Ist `cn` als IP-Adresse parsbar, erzeugt rcgen einen IP-SAN, sonst einen DNS-SAN
  [lib.rs:generate_server_tls]
- Die Gültigkeit ist fest auf 3650 Tage ab `time::OffsetDateTime::now_utc()` gesetzt;
  `not_before` wird nie gesetzt und behält den rcgen-Default 1975-01-01
  [lib.rs:generate_server_tls]
- Das Zertifikat ist mit dem im selben Aufruf erzeugten Schlüssel selbstsigniert
  (`params.self_signed(&key_pair)`) — keine CA-Kette, kein ausstellender Trust-Store
  [lib.rs:generate_server_tls]
- Der Schlüssel wird mit dem rcgen-Default `PKCS_ECDSA_P256_SHA256` erzeugt und an
  rustls als PKCS#8-DER übergeben (`PrivateKeyDer::Pkcs8(...)`)
  [lib.rs:generate_server_tls]
- Die `ServerConfig` enthält genau ein Zertifikat (`with_single_cert`) und verlangt
  kein Client-Zertifikat (`with_no_client_auth`) [lib.rs:generate_server_tls]
- `ServerTls::cert_pem` und `ServerTls::key_pem` sind die PEM-Kodierungen genau
  desselben Zertifikats und Schlüssels, die als DER in die Config eingeflossen sind;
  beide Darstellungen korrespondieren daher immer [lib.rs:generate_server_tls]
- Der Trust-Store des Clients startet leer (`RootCertStore::empty()`) und enthält
  ausschließlich die aus dem übergebenen PEM geparsten Zertifikate — kein System- oder
  Native-Root-Store wird geladen [lib.rs:client_config_trusting]
- Jedes Zertifikat im übergebenen PEM wird in den Trust-Store aufgenommen; ein
  Multi-Zertifikat-PEM ergibt damit mehrere Trust-Anker [lib.rs:client_config_trusting]
- Die Client-Config führt keine Client-Authentifizierung durch (`with_no_client_auth`)
  [lib.rs:client_config_trusting]
- Die Fehlerabbildung ist fest: jeder rcgen-Fehler (Params, Schlüsselerzeugung,
  Selbstsignieren) wird zu `TlsError::CertGen`; PEM-Parsefehler und fehlgeschlagene
  Trust-Store-Aufnahme werden beide zu `TlsError::PemLoad`; ein Fehler beim Bau der
  rustls-Server-Config wird zu `TlsError::Config`. Der Client-Pfad erzeugt nie
  `TlsError::Config` [lib.rs:generate_server_tls] [lib.rs:client_config_trusting]

## Side Effects
- `KeyPair::generate()` zieht bei jedem Aufruf frische Entropie aus dem OS-RNG; jeder
  Aufruf liefert daher einen anderen Schlüssel und nicht reproduzierbare
  Zertifikatsbytes [lib.rs:generate_server_tls]
- `time::OffsetDateTime::now_utc()` liest die Systemuhr des Prozesses; die
  Gültigkeitsdauer des Zertifikats hängt damit von der Wanduhr ab
  [lib.rs:generate_server_tls]
- `ServerConfig::builder()` und `ClientConfig::builder()` lösen den prozessweiten
  `CryptoProvider` auf; da der Workspace nur das rustls-Feature `ring` aktiviert,
  installiert der erste Builder-Aufruf den ring-Provider als prozessweiten Default
  (prozessweite Zustandsänderung) und paniked bei mehrdeutiger Provider-Auflösung
  [lib.rs:generate_server_tls] [lib.rs:client_config_trusting]
- Der private Schlüssel wird im Klartext-PEM im zurückgegebenen Struct exponiert
  (`ServerTls::key_pem`) [lib.rs:ServerTls]
- Keine Datei-, Netzwerk-, Log-, Datenbank- oder sonstigen I/O-Nebenwirkungen: der
  Crate liest keine Dateien (PEM wird als Bytes übergeben), öffnet keine Sockets und
  schreibt nichts [lib.rs:generate_server_tls] [lib.rs:client_config_trusting]

## Verification
- Run: `cargo test` (Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Der Crate selbst bringt keine Tests mit (`cargo test -p kx-tls` meldet 0 Tests).
  Der Workspace-Gesamtlauf schlägt auf macOS derzeit beim Kompilieren von `kx-scanner`
  fehl (Linux-spezifische `libc`-Konstanten), nicht in `kx-tls`.
