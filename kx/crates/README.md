# kx/crates

## Overview

`kx/crates/` enthält die neun Member-Crates des Rust-Workspace `kx`. Die
Workspace-Definition in [`../Cargo.toml`](../Cargo.toml) bindet sie über
`[workspace] members = [...]` mit `resolver = "2"` ein; jedes Crate besitzt ein
eigenes `Cargo.toml` und erbt Version, Edition, MSRV, Lizenz und Autoren per
`*.workspace = true` aus dem Workspace-Manifest.

Die Crates bilden eine strenge Schichtung: `kx-core` und `kx-scanner` sind
Basislagen ohne interne Crate-Abhängigkeit, darüber liegen TLS- und
Post-Exploitation-Schicht, darüber die drei Binaries. `kx-agent` ist der
einzige Crate, der alle Fachbereiche zusammenbindet.

```
kx-core ──┬──> kx-tls ──┬──> kx-server
          │              └──> kx-cli
          ├──> kx-win
          ├──> kx-posix
          └──> kx-agent <── kx-exploit <── kx-scanner
                │  └────────────┴── kx-win, kx-posix, kx-scanner, kx-tls
```

`kx-agent` ist der einzige Crate, der **sechs** interne Crates einbindet
(`kx-core`, `kx-scanner`, `kx-exploit`, `kx-win`, `kx-posix`, `kx-tls`) — er
bindet damit alle Fachbereiche zusammen.

## Subdirectories & Boundaries

- [kx-agent](./kx-agent/README.md) — Autonomer Kx-Agent: Ausbreitung, C2-Kommunikation, Task-Verarbeitung. Bindet Scanner, Exploit-, Win- und POSIX-Persistenz sowie TLS aneinander; einziges Crate mit sechs internen Abhängigkeiten.
- [kx-cli](./kx-cli/README.md) — Kx-CLI: Operator-Interface für C2-Steuerung. `clap`-basierte Binär-Crate für Host-, Secret- und Task-Abfragen sowie den Export; nutzt `kx-tls` für den TLS-Trust und `kx_core::c2` für die Nachrichtentypen und Pfadkonstanten.
- [kx-core](./kx-core/README.md) — Encoder-Kern: KXENC-Dateiformat, Fehlerklassifikation, plattformneutrale Hilfsfunktionen und das C2-Protokollmodul `c2`. Das Manifest beschreibt zusätzlich „Hybrid-KEM, AEAD-Chunks, Scan-Policy, Journal, Engine" — Scan-Policy, Journal und Engine existieren im Code **nicht**, und der Hybrid-KEM-Teil (`hostkey`) ist auskommentiert und wird nicht kompiliert. Plattformneutral und ohne interne Crate-Abhängigkeit; Basis aller anderen Crates.
- [kx-exploit](./kx-exploit/README.md) — Exploit-Module: SMB-Relay, Credential-Stuffing via Impacket. Einzige Crate mit eigenem Unterverzeichnis [`examples/`](./kx-exploit/examples/README.md); stützt sich auf `kx-scanner`.
- [kx-posix](./kx-posix/README.md) — POSIX-Post-Exploitation: Secrets-Extraktion (Shadow, SSH, AWS) und Persistence (systemd, Cron). Jede öffentliche Funktion existiert doppelt als `#[cfg(unix)]`-Variante und Nicht-Unix-Stub.
- [kx-scanner](./kx-scanner/README.md) — Netzwerkerkennung und Service-Fingerprinting für den Kx-Netzwerkwurm. Basislage ohne interne Crate-Abhängigkeit; liefert die Scan-Ergebnisse an `kx-exploit` und `kx-agent`.
- [kx-server](./kx-server/README.md) — Kx-C2-Server: Host-Registry, Secret-Store, Dashboard. axum-API mit SQLite-Persistenz und selbstsigniertem TLS über `kx-tls`. Eine Token-Durchsetzung findet derzeit **nicht** statt: kein Handler verwendet den `Authenticated`-Extractor, und `AppState.token` wird nie gelesen.
- [kx-tls](./kx-tls/README.md) — TLS-Infrastruktur für Kx (rustls-basiert). Erzeugt selbstsignierte Zertifikate und baut Server- und Client-Configs; keine Datei-, Netzwerk- oder sonstigen I/O-Nebenwirkungen.
- [kx-win](./kx-win/README.md) — Windows-Post-Exploitation: Secrets-Extraktion (LSASS, Credential Manager, Browser) und Persistence. Analog zu `kx-posix` mit Windows- und Nicht-Windows-Variante.

## Interface

- [`../Cargo.toml`](../Cargo.toml) — Workspace-Manifest: `[workspace]` mit den neun Membern, `[workspace.package]` mit `version = "0.1.0"`, `edition = "2021"`, `rust-version = "1.77"`, `license = "MIT"`, `authors = ["Red Team Reference"]`.
- [`../Cargo.toml`](../Cargo.toml) — `[workspace.dependencies]`: interne Crates als `path`-Dependencies (`kx-core`, `kx-win`, `kx-posix`, `kx-tls`, `kx-scanner`, `kx-exploit`). Alle neun Crates referenzieren ihre internen Abhängigkeiten über `{ workspace = true }` und damit über diese zentrale Definition; `kx-agent`, `kx-server` und `kx-cli` binden dieselben Einträge ein, definieren aber keine eigenen.
- [`../Cargo.toml`](../Cargo.toml) — `[profile.release]`: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `panic = "unwind"`, `strip = "debuginfo"`.
- [`../Cargo.toml`](../Cargo.toml) — `[profile.dev]`: `opt-level = 1`.

## Invariants

- Die neun Crates sind die einzigen Workspace-Mitglieder; ein Crate außerhalb dieser Liste wird von `[workspace] members` nicht erfasst [`../Cargo.toml`](../Cargo.toml).
- Alle Crates erben `version`, `edition`, `rust-version` und `license` aus `[workspace.package]` und überschreiben keinen dieser Werte. `authors` erben nur acht der neun Crates — `kx-core/Cargo.toml` enthält kein `authors.workspace = true`.
- `kx-core` und `kx-scanner` deklarieren keine interne Crate-Abhängigkeit — beide sind Basislagen.
- Interne Crate-Abhängigkeiten sind ausschließlich `path`-Dependencies auf die Workspace-Crates; keine Registry-Version dieser Crates wird verwendet.
- `kx-agent` ist der einzige Crate, der `kx-exploit`, `kx-posix`, `kx-scanner`, `kx-tls` und `kx-win` gleichzeitig einbindet.
- `ml-kem` ist im Workspace-Manifest auf die exakte Version `=0.2.1` festgenagelt [`../Cargo.toml`](../Cargo.toml). Der einzige konsumierende Crate umgeht diesen Pin jedoch: `kx-core/Cargo.toml` deklariert `ml-kem` eigenständig mit `version = "0.2.1"` ohne `=`-Pin und ohne `workspace = true` — aufgelöst wird tatsächlich **0.2.3** (`kx/Cargo.lock`). Der Pinwert `=0.2.1` ist zudem keine valide Zielversion: `ml-kem` 0.2.1 verlangt `kem` per Caret und lässt `kem` 0.3.0 zu, was `rand_core` 0.10.1 neben die 0.6.4 des Workspaces zieht — 18 Compile-Errors, verifiziert. Korrekt ist `=0.2.3` [ISSUE-8](../../.scratch/c2-operability/issues/ISSUE-8-ml-kem-pin-umgangen.md).
- `panic = "unwind"` bleibt im Release-Profil aktiv, weil der Encoder pro Datei einen Panic abfangen muss [`../Cargo.toml`](../Cargo.toml).

## Side Effects

- `kx/crates/` enthält den gesamten Rust-Quellcode des Projekts (43 `.rs`-Dateien in neun Crates). Die externen Effekte liegen ausschließlich in den `src/`-Modulbäumen der Crates und sind dort einzeln dokumentiert.
- Beim Bauen entstehen Rust-Artefakte im gemeinsamen Target-Verzeichnis `kx/target/`; ein Cargo-Workspace hat genau **ein** solches Verzeichnis, `crates/*/target` existiert nicht. Die Artefakte sind Build-Ausgabe und kein Teil des Vertrags.
- Zusammengefasst über alle Crates: Raw-Socket-Versand und TCP-Verbindungen (`kx-scanner`), Subprozesse (`kx-exploit`), Dateischreibzugriffe und `systemctl`/`crontab` (`kx-posix`), Registry- und Dienstinstallation (`kx-win`), SQLite-Datei und TLS-Listener (`kx-server`), HTTP-POSTs an den C2-Server (`kx-agent`), Exportdateien (`kx-cli`).

## Verification

- Run: `cd /Volumes/T7/Projekte/testwurm/kx && cargo test`
- Stand: `cargo test --workspace` läuft auf macOS grün durch (59 Tests, 0 Fehler). `kx-scanner/src/arp.rs` ist vollständig mit `#[cfg(target_os = "linux")]` ausgezeichnet; der ARP-Sweep existiert damit nur auf Linux.
