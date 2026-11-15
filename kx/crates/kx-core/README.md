# kx-core

## Overview

`kx-core` ist der plattformneutrale Encoder-Kern des Kx-Workspace. Er enthaelt das
Dateiformat `KXENC` v1 (Layout, Reichweitenplanung, Nonce- und AAD-Regeln), die
Fehlerklassifikation, die kryptografischen Hilfsfunktionen, die alle anderen
Crates konsumieren, und das C2-Protokoll (`c2.rs`) als einzige Definition des
Wire-Vertrags zwischen Wurm-Agent und Operator-C2.

Die Schichtgrenzen sind fest vorgegeben: `format` → `crypto` → `engine` → `beacon`.
Das Beacon kennt den Encoder, der Encoder kennt kein Beacon. Alles in diesem Crate
ist Plattformcode-frei; Windows- und POSIX-Spezifika stecken in `kx-win` und
`kx-posix`.

Crate-Metadaten aus `Cargo.toml`: Name `kx-core`, Version `0.1.0` (aus
`[workspace.package]`), Edition `2021`, MSRV `1.77`, Lizenz `MIT`. Abhaengigkeiten:
`serde`, `serde_json`, `sha2`, `hkdf`, `argon2`, `chacha20poly1305`, `x25519-dalek`,
`ml-kem` (aus dem Workspace ueber `.workspace = true`, **auf `=0.2.3` gepinnt**;
Features `std` + `zeroize`), `rand_core`, `zeroize`, `thiserror`,
`base64`; Dev-Dependency `rand`.
Es gibt damit genau **eine** Stelle, an der die `ml-kem`-Version steht: der
Workspace-Pin `ml-kem = { version = "=0.2.3", … }` in `kx/Cargo.toml`. Vorher
deklarierte `kx-core` die Dependency selbst mit einem Caret-Bereich und umging
den Pin dadurch — es wurde 0.2.3 aufgeloest statt der beabsichtigten Version.
Der Pin steht auf 0.2.3 und nicht auf 0.2.1, weil `ml-kem` 0.2.1 die
`kem`-Abhaengigkeit mit dem Caret-Bereich `0.3.0-pre.0` deklariert: dadurch
wird `kem` 0.3.0 aufgeloest, das zieht `rand_core` 0.10.1 neben die 0.6.4 des
Workspaces, und die Trait-Definitionen sind inkompatibel — der Build bricht.
0.2.3 pinnt `kem` exakt auf `=0.3.0-pre.0` und bleibt bei einer einzigen
`rand_core`-Version.
Das `deterministic`-Feature von `ml-kem` ist
absichtlich aus: es verlangt vom Aufrufer, das Kapselungsgeheimnis `m` selbst
mitzubringen — ein Fehler dort waere ein totaler Schluesselverlust. `ml-kem` 0.3.x
waere moeglich, hebt aber `rand_core` auf 0.10, bricht `x25519-dalek` 2 und `rand` 0.8
und setzt die MSRV auf 1.87.

Das Modul `hostkey` (per-Host-Schluessel, Hybrid-KEM) liegt im Quellbaum, ist aber
nicht Teil des Builds — siehe [src/README.md](./src/README.md).

## Subdirectories & Boundaries

- [src](./src/README.md) - Vollständige Implementierung des Encoder-Kerns: `lib.rs` (Crate-Wurzel mit den Formatkonstanten), `c2.rs` (C2-Protokoll: Endpunktpfade, Host-Status, Wire-Typen), `error.rs` (Fehlerklassifikation `ErrorClass`/`Error`), `format.rs` (KXENC-v1-Dateiformat, Reichweitenplanung, Nonce/AAD) und `util.rs` (plattformneutrale Hilfsfunktionen). `hostkey.rs` liegt im Quellbaum, ist aber nicht kompiliert.

## Interface

- `pub mod c2;` — C2-Protokoll: Endpunktpfade, Host-Status, Wire-Typen `[src/lib.rs:c2]`
- `pub mod c2;` — C2-Protokoll: Endpunktpfade, Host-Status, Wire-Typen `[src/lib.rs:c2]`
- `pub mod error;` — Fehlerklassen und Fehler-Typ `[src/lib.rs:error]`
- `pub mod format;` — `KXENC`-Dateiformat, Reichweitenplanung, Nonce/AAD `[src/lib.rs:format]`
- `pub mod util;` — Base64, Hex, SHA-256, CRC-32, Zeit, kanonisches JSON, Jitter `[src/lib.rs:util]`
- `pub use error::{Error, Result};` — Re-Export der Fehlertypen an der Crate-Wurzel `[src/lib.rs:Error]`
- `pub const FORMAT_VERSION: u8 = 1;` — Formatversion, die dieser Build lesen und schreiben kann `[src/lib.rs:FORMAT_VERSION]`
- `pub const READABLE_FORMAT_VERSIONS: [u8; 1] = [1];` — aeltere, weiterhin lesbare Formatversionen `[src/lib.rs:READABLE_FORMAT_VERSIONS]`
- `pub const FORMAT_NAME: &str = "KXENC";` — Formatbezeichnung fuer Werkzeuge und Doku `[src/lib.rs:FORMAT_NAME]`
- `pub const MAX_RANGES: usize = 2;` — maximale Anzahl verschluesselter Bereiche pro Datei `[src/lib.rs:MAX_RANGES]`
- Kinddokumentation der Module: [src/README.md](./src/README.md)

## Invariants

- Das Crate ist weitgehend Plattformcode-frei: Windows- und POSIX-Spezifika stecken in `kx-win` und `kx-posix`. Ein Trait oder Modul `platform::PlatformHooks` existiert im Code **nicht** — der Modul-Doc-Comment in `lib.rs:8` beschreibt es nur prosaisch `[src/lib.rs:PlatformHooks]`
- **Ausnahme:** `error.rs` enthält per `#[cfg(unix)]` und `#[cfg(windows)]` getrennte POSIX-errno- und Win32-Code-Tabellen für `class_from_errkind` — je Build existiert nur eine der beiden Tabellen [src/error.rs:class_from_errkind]
- Die Abhaengigkeitsrichtung ist fest: `format` → `crypto` → `engine` → `beacon`; das Beacon kennt den Encoder, der Encoder kennt kein Beacon `[src/lib.rs:beacon]`
- `MAX_RANGES` ist konstant, damit das Format keine variable Laenge im Footer traegt `[src/lib.rs:MAX_RANGES]`
- `FORMAT_VERSION` ist die Version, die dieser Build lesen und schreiben kann; `READABLE_FORMAT_VERSIONS` listet die aelteren, weiterhin lesbaren Versionen `[src/lib.rs:FORMAT_VERSION]` `[src/lib.rs:READABLE_FORMAT_VERSIONS]`
- `pub mod hostkey;` ist in `lib.rs` in Zeile 13 auskommentiert (`// pub mod hostkey;  // TODO: ml-kem 0.2.1-API-Anpassungen noetig, vorerst deaktiviert`); das Modul ist damit nicht Teil der oeffentlichen API und wird nicht kompiliert `[src/lib.rs:hostkey]`
- Die `ml-kem`-Version steht an genau **einer** Stelle: dem Workspace-Pin `=0.2.3` in `kx/Cargo.toml`. `kx-core` bezieht die Dependency ueber `.workspace = true` und kann sie dadurch nicht mehr umgehen `[src/lib.rs:mlkem_api_used_by_hostkey_is_available]`
- Der Pin steht auf 0.2.3 und nicht auf 0.2.1, weil 0.2.1 `kem` mit einem Caret-Bereich deklariert: es wird `kem` 0.3.0 aufgeloest, das zieht `rand_core` 0.10.1 neben die 0.6.4 des Workspaces, und die Trait-Definitionen sind inkompatibel — der Build bricht. 0.2.3 haelt genau eine `rand_core`-Version im Lockfile `[src/lib.rs:mlkem_api_used_by_hostkey_is_available]`
- Das C2-Protokoll ist asymmetrisch strikt: die Antworttypen `Host`, `ExfiltratedSecret` und `Task` tragen `#[serde(deny_unknown_fields)]`, die Request-Typen `RegisterRequest`, `HeartbeatRequest`, `SecretUpload`, `CreateTaskRequest` und `TaskResultRequest` sind lenient — additive Erweiterung eines Agenten bricht einen älteren Server nicht `[src/c2.rs:Host]` `[src/c2.rs:Task]` `[src/c2.rs:RegisterRequest]`
- Der neue Pfad `PATH_LOGIN` (`/api/login`) ist eine **Antwort** und damit strikt; `LoginRequest` ist ein Request und damit lenient `[src/c2.rs:PATH_LOGIN]` `[src/c2.rs:LoginRequest]`

## Side Effects

- Der einzige externe Zugriff im Crate ist der Systemuhr-Read in `util::now_rfc3339` und `util::now_unix` (`std::time::SystemTime::now()`) `[src/util.rs:now_rfc3339]` `[src/util.rs:now_unix]`
- `util::jitter` schreibt den neuen xorshift64*-Zustand in den vom Aufrufer gelieferten Seed zurueck `[src/util.rs:jitter]`
- `util::Sha256Stream::update` mutiert den ueber `&mut self` fortgeschriebenen Hashzustand `[src/util.rs:update]`
- `format::FooterFlags::insert` und `format::FooterFlags::remove` mutieren den Flag-Wert des Aufrufers in place `[src/format.rs:FooterFlags::insert]` `[src/format.rs:FooterFlags::remove]`
- `format::aad_for` leert den uebergebenen `&mut Vec<u8>` und befuellt ihn mit den AAD-Bytes `[src/format.rs:aad_for]`
- `c2.rs` ist reines Datenmodell ohne Datei-, Netzwerk- oder Prozesszugriff; die (De-)Serialisierung allokiert je Wire-Feld einen `String` `[src/c2.rs:Host]` `[src/c2.rs:SecretUpload]`
- Zufallsverbrauch, Stack-Nullung von Secrets und der Argon2id-Speicherbedarf existieren nur im nicht kompilierten Modul `hostkey` und haben derzeit keine Wirkung `[src/hostkey.rs:ServerKeyBundle::generate]` `[src/hostkey.rs:Drop for MlKemSecret]` `[src/hostkey.rs:argon2id]`

## Verification

- Run: `cargo test` (ausgefuehrt in `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` ist gruen — **59 Tests, 0 Fehler**; davon `cargo test -p kx-core`: **31 Tests, 0 Fehler** (11 in `c2.rs`, 10 in `format.rs`, 7 in `util.rs`, 2 in `error.rs`, 1 in `lib.rs`)
