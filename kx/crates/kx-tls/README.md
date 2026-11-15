# kx-tls

## Overview
`kx-tls` ist die TLS-Infrastruktur des Kx-Workspace: eine dünne, rustls-basierte
Schicht, die selbstsignierte X.509-Zertifikate erzeugt und daraus
`rustls::ServerConfig`- bzw. `rustls::ClientConfig`-Objekte baut. Der Crate besteht
aus genau einer Quelldatei (`src/lib.rs`) und bringt weder eigene Zustandsverwaltung,
Persistenz noch Netzwerkzugriff mit — er liefert ausschließlich TLS-Material.

Der Server-Pfad (`generate_server_tls`) wird vom C2-Backend
[kx-server/src/main.rs:234](../kx-server/src/main.rs) genutzt, um das
HTTPS-Listener-Zertifikat zu erzeugen. Der Client-Pfad (`client_config_trusting`)
wird vom Wurm [kx-agent/src/c2.rs:47](../kx-agent/src/c2.rs) und von der
Operator-CLI [kx-cli/src/client.rs:43](../kx-cli/src/client.rs) verwendet, um
ausschließlich dem Server-Zertifikat zu vertrauen.

Abhängigkeiten laut [Cargo.toml](./Cargo.toml): `rustls`, `rustls-pemfile`,
`rustls-pki-types`, `rcgen`, `thiserror`, `time`. `kx-core` stand früher im
Manifest, wurde im Quellcode des Crates aber nirgends referenziert; die Kante
ist entfernt, damit `kx-core` den C2-Transport aufnehmen kann — der braucht
das TLS-Vertrauen aus diesem Crate, und eine Kante in beide Richtungen wäre
ein Zyklus.

## Subdirectories & Boundaries

- [src](./src/README.md) - Die einzige Quelldatei des Crates (`src/lib.rs`): Fehlerenum `TlsError`, Struct `ServerTls`, `generate_server_tls` und `client_config_trusting`. Sämtliche externen Effekte stecken ausschließlich in diesem Modulbaum.

## Interface
- `pub enum TlsError` — Fehlerarten des Crates mit den Varianten `CertGen(String)`,
  `PemLoad(String)` und `Config(String)` [src/lib.rs:TlsError]
- `pub struct ServerTls` — Bündel aus `config: Arc<ServerConfig>`,
  `cert_pem: Vec<u8>` und `key_pem: Vec<u8>` [src/lib.rs:ServerTls]
- `pub fn generate_server_tls(cn: &str) -> Result<ServerTls, TlsError>` — erzeugt ein
  selbstsigniertes Zertifikat für den angegebenen CN und liefert dazu die
  rustls-Server-Config sowie die PEM-Daten [src/lib.rs:generate_server_tls]
- `pub fn client_config_trusting(cert_pem: &[u8]) -> Result<Arc<ClientConfig>, TlsError>`
  — baut eine Client-Config, die genau den im PEM enthaltenen Zertifikaten vertraut
  [src/lib.rs:client_config_trusting]
- Implementierung und Modulvertrag: [src/README.md](./src/README.md)

## Invariants
- Der `cn`-Parameter wird ausschließlich als Subject-Alternative-Name verwendet
  (`CertificateParams::new(vec![cn.to_string()])`); der Subject-DN bleibt beim
  rcgen-Default ("rcgen self signed cert"), der Subject-CN ist also *nicht* der
  übergebene Wert [src/lib.rs:generate_server_tls]
- Ist `cn` als IP-Adresse parsbar, erzeugt rcgen einen IP-SAN, sonst einen DNS-SAN
  [src/lib.rs:generate_server_tls]
- Die Gültigkeit ist fest auf 3650 Tage ab `time::OffsetDateTime::now_utc()` gesetzt;
  `not_before` wird nie gesetzt und behält den rcgen-Default 1975-01-01
  [src/lib.rs:generate_server_tls]
- Das Zertifikat ist mit dem im selben Aufruf erzeugten Schlüssel selbstsigniert
  (`params.self_signed(&key_pair)`) — keine CA-Kette, kein ausstellender Trust-Store
  [src/lib.rs:generate_server_tls]
- Der Schlüssel wird mit dem rcgen-Default `PKCS_ECDSA_P256_SHA256` erzeugt und an
  rustls als PKCS#8-DER übergeben (`PrivateKeyDer::Pkcs8(...)`)
  [src/lib.rs:generate_server_tls]
- Die `ServerConfig` enthält genau ein Zertifikat (`with_single_cert`) und verlangt
  kein Client-Zertifikat (`with_no_client_auth`) [src/lib.rs:generate_server_tls]
- `ServerTls::cert_pem` und `ServerTls::key_pem` sind die PEM-Kodierungen genau
  desselben Zertifikats und Schlüssels, die als DER in die Config eingeflossen sind;
  beide Darstellungen korrespondieren daher immer [src/lib.rs:generate_server_tls]
- Der Trust-Store des Clients startet leer (`RootCertStore::empty()`) und enthält
  ausschließlich die aus dem übergebenen PEM geparsten Zertifikate — kein System- oder
  Native-Root-Store wird geladen [src/lib.rs:client_config_trusting]
- Jedes Zertifikat im übergebenen PEM wird in den Trust-Store aufgenommen; ein
  Multi-Zertifikat-PEM ergibt damit mehrere Trust-Anker [src/lib.rs:client_config_trusting]
- Die Client-Config führt keine Client-Authentifizierung durch (`with_no_client_auth`)
  [src/lib.rs:client_config_trusting]
- Die Fehlerabbildung ist fest: jeder rcgen-Fehler (Params, Schlüsselerzeugung,
  Selbstsignieren) wird zu `TlsError::CertGen`; PEM-Parsefehler und fehlgeschlagene
  Trust-Store-Aufnahme werden beide zu `TlsError::PemLoad`; ein Fehler beim Bau der
  rustls-Server-Config wird zu `TlsError::Config`. Der Client-Pfad erzeugt nie
  `TlsError::Config` [src/lib.rs:generate_server_tls] [src/lib.rs:client_config_trusting]

## Side Effects
- `KeyPair::generate()` zieht bei jedem Aufruf frische Entropie aus dem OS-RNG; jeder
  Aufruf liefert daher einen anderen Schlüssel und nicht reproduzierbare
  Zertifikatsbytes [src/lib.rs:generate_server_tls]
- `time::OffsetDateTime::now_utc()` liest die Systemuhr des Prozesses; die
  Gültigkeitsdauer des Zertifikats hängt damit von der Wanduhr ab
  [src/lib.rs:generate_server_tls]
- `ServerConfig::builder()` und `ClientConfig::builder()` lösen den prozessweiten
  `CryptoProvider` auf. `install_crypto_provider()` setzt ihn vorher explizit auf
  `ring`; der Workspace aktiviert nur das rustls-Feature `ring`, und `axum-server`
  bringt über `tls-rustls-no-provider` keinen zweiten Provider mit. Ohne die
  explizite Installation wäre die Auflösung ein `panic!` an der Stelle, an der
  jemand die TLS-Konfiguration baut [src/lib.rs:install_crypto_provider]
  [src/lib.rs:generate_server_tls] [src/lib.rs:client_config_trusting]
- `install_crypto_provider()` ist idempotent: ein zweiter Aufruf liefert einen
  Fehler, der ignoriert wird — der Provider bleibt der erste installierte
  [src/lib.rs:install_crypto_provider]
- Der private Schlüssel wird im Klartext-PEM im zurückgegebenen Struct exponiert
  (`ServerTls::key_pem`) [src/lib.rs:ServerTls]
- Keine Datei-, Netzwerk-, Log-, Datenbank- oder sonstigen I/O-Nebenwirkungen: der
  Crate liest keine Dateien (PEM wird als Bytes übergeben), öffnet keine Sockets und
  schreibt nichts. Die Provider-Installation ist eine prozessweite
  Zustandsänderung, aber kein I/O [src/lib.rs:generate_server_tls] [src/lib.rs:client_config_trusting]

## Verification
- Run: `cargo test` (Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Der Crate selbst bringt keine Tests mit (`cargo test -p kx-tls` meldet 0 Tests).
  Der Workspace-Gesamtlauf schlägt auf macOS derzeit beim Kompilieren von `kx-scanner`
  fehl (Linux-spezifische `libc`-Konstanten), nicht in `kx-tls`.
