# kx-cli

## Overview

Rust-Binärcrate `kx-cli` (Version 0.1.0, Edition 2021, MSRV 1.77, Lizenz MIT) im Kx-Workspace. Das Manifest [Cargo.toml](./Cargo.toml) beschreibt die Operator-Oberfläche des Kx-C2-Servers und deklariert die Abhängigkeiten `kx-core`, `serde`, `serde_json`, `clap`, `tracing`, `tracing-subscriber`, `thiserror` und `tokio`.

Dieses Verzeichnis enthält keine direkten Quelldateien; der gesamte Rust-Code liegt in `src/`. Von den Workspace-Crates wird nur `kx-core` im Code verwendet — die Protokolltypen aus `kx_core::c2` [src/client.rs:Client::hosts] und der Transport aus `kx_core::c2::transport` [src/client.rs:Client::new]. `kx-tls` und `ureq` sind aus dem Manifest entfernt: der Transport bringt das TLS-Vertrauen und den HTTP-Client mit.

Die Verifikation erfolgt über `cargo test` aus der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`.

## Subdirectories & Boundaries

- [src](./src/README.md) - Clap-Frontend (`main.rs`) sowie TLS-gesicherter HTTP-Client mit Secret-Export (`client.rs`).

## Interface

Rollup aus [`src/`](./src/README.md):

- `#[derive(Parser)]` `Cli` mit den Top-Level-Argumenten `--server` (Env `KX_C2_URL`), `--token` (Env `KX_C2_TOKEN`) und `--cert` sowie den Subcommands `hosts`, `secrets` (Flag `--user`), `export` (positionelles `path`, Flag `--format`), `tasks` und `task-create` (Flags `--host-id` und `--command`) [src/main.rs:Cli] [src/main.rs:Command]. Die drei Argumente sind **keine** clap-`global`-Flags (`global = true` fehlt in `src/main.rs:17,20,23`) — sie müssen **vor** dem Subcommand stehen; `kx-cli hosts --server https://x` scheitert mit „unexpected argument '--server' found“.
- `pub struct Client` mit `pub fn new`, `pub async fn hosts`, `pub async fn secrets`, `pub async fn tasks`, `pub async fn create_task` sowie `pub fn export` — alle Items sind mangels `lib.rs` crate-intern [src/client.rs:Client] [src/client.rs:export].
- `pub enum ApiError` mit `Transport(TransportError)` (`#[error(transparent)]`) und `Io(String)`; die Transportfehler kommen aus `kx_core::c2::transport` [src/client.rs:ApiError].
- Datenmodelle `Host`, `ExfiltratedSecret` und `Task` stammen aus `kx_core::c2` [../kx-core/src/c2.rs:Host] [../kx-core/src/c2.rs:ExfiltratedSecret] [../kx-core/src/c2.rs:Task]; ein eigener Typ `Secret` existiert im Crate nicht.
- Endpunktpfade über die Konstanten `PATH_HOSTS`, `PATH_SECRETS` und `PATH_TASKS` [../kx-core/src/c2.rs:PATH_HOSTS] [../kx-core/src/c2.rs:PATH_SECRETS] [../kx-core/src/c2.rs:PATH_TASKS].

## Invariants

Rollup aus [`src/`](./src/README.md):

- Die Crate ist binary-only; es existiert keine `lib.rs`, daher bilden alle `pub`-Items keine exportierte Bibliotheks-API [src/main.rs:mod client].
- Die Wire-Typen `Host`, `ExfiltratedSecret` und `Task` tragen `#[serde(deny_unknown_fields)]`; jedes unbekannte Feld im Server-JSON bricht die Deserialisierung ab und wird zu `TransportError::Json` [../kx-core/src/c2.rs:Host] [../kx-core/src/c2/transport.rs:parse_json].
- `Host` hat das Feld `host_id` (nicht `id`); `Task` hat das verpflichtende Feld `result: String` und **kein** optionales Feld [../kx-core/src/c2.rs:Host] [../kx-core/src/c2.rs:Task].
- Die Base-URL wird über `trim_end_matches('/')` normalisiert [../kx-core/src/c2/transport.rs:Transport::new].
- Der Auth-Header ist exakt `Authorization: Bearer {token}`; Query-Parameter werden nie angehängt [../kx-core/src/c2/transport.rs:build_request].
- Das TLS-Vertrauen ist auf exakt die im `--cert`-PEM enthaltenen Zertifikate gepinnt; der Root-Store startet leer und es wird kein Client-Zertifikat präsentiert [../kx-tls/src/lib.rs:client_config_trusting].
- Der Export verzweigt auf ein exaktes Match gegen `"csv"`; jeder andere Wert wird als Pretty-JSON serialisiert [src/client.rs:export].
- Die CSV-Kopfzeile lautet exakt `host_id,cred_type,username,password,source,collected_at`; `ExfiltratedSecret.id` wird im CSV nicht ausgegeben [src/client.rs:export].
- Der Filter `--user` ist ein Substring-Test auf `s.username`; ohne `--user` bleiben alle Secrets erhalten [src/main.rs:Command::Secrets].
- Jeder Fehlerpfad beendet den Prozess mit Exit-Code 1. Argumentationsfehler von clap beenden mit **Exit-Code 2** (`Cli::parse()` in `src/main.rs:61`), `--help` endet mit 0 [src/main.rs:main].

## Side Effects

Rollup aus [`src/`](./src/README.md):

- Dateisystem-Leszugriff: `std::fs::read(cert)` liest die PEM-Datei bei jeder Client-Konstruktion [../kx-core/src/c2/transport.rs:Transport::from_cert_file].
- Netzwerk: HTTP GET auf `/api/hosts`, `/api/secrets` und `/api/tasks`, HTTP POST auf
  `/api/tasks/new` [src/client.rs:Client::hosts] [src/client.rs:Client::secrets]
  [src/client.rs:Client::tasks] [src/client.rs:Client::create_task].
- Dateisystem-Schreibzugriff: `std::fs::File::create` legt die Exportdatei an oder überschreibt sie; geschrieben werden die Secrets im Klartext, im JSON-Zweig inklusive `id` und `password` [src/client.rs:export].
- stdout-Schreibzugriffe pro Host, Secret und Task; `std::process::exit(1)` bei jedem Fehlerpfad [src/main.rs:main].
- Globaler Zustand: `tracing_subscriber` installiert den prozessweiten Subscriber [src/main.rs:main].

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` läuft grün (130 Tests, 0 Fehler), davon 3 in `kx-cli` — `export_writes_csv`, `cli_reads_the_task_result_from_server_json` und `cli_reads_hosts_and_secrets_from_server_json`.
