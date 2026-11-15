# kx-agent

## Overview

Manifest des Rust-Crates `kx-agent` (`[Cargo.toml:package]`, Name `kx-agent`, Beschreibung
„Autonomer Kx-Agent: Ausbreitung, C2-Kommunikation, Task-Verarbeitung"). Das Crate ist ein
Binary-Crate: `src/main.rs` ist der einzige Entry-Point und erzeugt das Executable `kx-agent`.
Es ist Mitglied des Workspace `kx` (`resolver = "2"`, Edition 2021, MSRV 1.77) und erbt
`version`, `edition`, `rust-version`, `license` und `authors` aus dem Workspace-Paketblock
(`[Cargo.toml:package]` mit `version.workspace = true` usw.).

Die Abhängigkeiten sind in `[Cargo.toml:dependencies]` deklariert: die Workspace-Crates
`kx-core`, `kx-scanner`, `kx-exploit`, `kx-win`, `kx-posix`, `kx-tls` sowie `serde`,
`serde_json`, `thiserror`, `tracing`, `tracing-subscriber`, `tokio`, `ureq`, `uuid`, `time`
und `clap`. Im Quellcode von `src/` referenziert werden davon `kx-tls`, `kx-win`, `kx-posix`,
`kx-scanner`, `kx-exploit`, `kx-core`, `thiserror`, `tracing`, `tracing-subscriber`, `tokio`,
`ureq` und `clap`; `serde`, `uuid` und `time` werden in `src/` nicht verwendet, und `serde_json`
ist nur über den Re-Export `ureq::serde_json` erreichbar [src/c2.rs:C2Client::register_host].

Der C2-Wire-Vertrag liegt nicht in diesem Crate, sondern in `kx_core::c2`; das Crate definiert
keine eigenen Payload-Typen, sondern nimmt `kx_core::c2::RegisterRequest` und
`kx_core::c2::SecretUpload` direkt entgegen [src/c2.rs:C2Client::register_host]
[src/c2.rs:C2Client::upload_secret].

## Subdirectories & Boundaries

- [src](./src/README.md) - Vollständige Implementierung des Agenten: `main.rs` (CLI-Argumentdefinition, Orchestrierung, lokale Secret-Extraktion, Persistenzinstallation), `c2.rs` (C2-Client mit ureq/rustls, HTTP-POSTs an `/api/register` und `/api/secrets`), `propagate.rs` (TCP-Scan, Dienst-Identifikation, SMB-Relay und Default-Credential-Angriffe).

## Interface

Rollup aus [`src/`](./src/README.md):

- `pub enum C2Error` mit `Http(String)`, `Tls(String)`, `Json(String)` [src/c2.rs:C2Error].
- `pub struct C2Client` mit privaten Feldern `agent: ureq::Agent`, `base_url: String`, `token: String`, sowie `pub fn new`, `pub async fn register_host` (POST `/api/register`), `pub async fn upload_secret` (POST `/api/secrets`), `pub async fn fetch_tasks` (GET `/api/tasks`) und `pub async fn report_task_result` (POST `/api/tasks/result`) [src/c2.rs:C2Client] [src/c2.rs:C2Client::new] [src/c2.rs:C2Client::register_host] [src/c2.rs:C2Client::upload_secret] [src/c2.rs:C2Client::fetch_tasks] [src/c2.rs:C2Client::report_task_result].
- `pub struct PropagationResults` mit genau zwei Feldern `new_hosts: Vec<RegisterRequest>` und `new_secrets: Vec<SecretUpload>` und `pub async fn run_propagation(discovered, relay_script)` [src/propagate.rs:PropagationResults] [src/propagate.rs:run_propagation].
- CLI-Oberfläche via `clap::Parser`: `--server`, `--token`, `--server-cert`, `--iface`, `--start`, `--end`, `--own-ip`, `--hosts`, `--relay-script` [src/main.rs:Args].
- Protokolltypen aus `kx_core::c2`: `RegisterRequest` (`host_id`, `ip`, `hostname`, `os`, `status`) und `SecretUpload` (`host_id`, `cred_type`, `username`, `password`, `source`) [../kx-core/src/c2.rs:RegisterRequest] [../kx-core/src/c2.rs:SecretUpload].

## Invariants

Rollup aus [`src/`](./src/README.md):

- Der Crate ist binary-only; `src/main.rs` ist der einzige Entry-Point, `c2.rs` und `propagate.rs` sind private Module ohne Bibliotheks-API [src/main.rs:main] [src/main.rs:mod c2].
- Die Host-ID ist die eigene IP (`own_ip.to_string()`); eine Funktion `local_host_id` existiert nicht mehr [src/main.rs:main].
- `PropagationResults` hat nur `new_hosts` und `new_secrets`; ein Feld `source_host` existiert nicht mehr, der Quellhost steht in jedem Element selbst [src/propagate.rs:PropagationResults].
- Der Agent registriert sich selbst vor der Extraktion, damit die lokal erbeuteten Secrets auf einen dem Server bekannten Host zeigen [src/main.rs:main].
- Die Ziel-Host-Kennung steht im Secret-Upload selbst und kann nicht mehr auseinanderlaufen [src/c2.rs:C2Client::upload_secret].
- Jeder Host wird genau einmal pro Propagationslauf registriert; der Push liegt nach der Port-Schleife [src/propagate.rs:run_propagation].
- Die Base-URL wird über `trim_end_matches('/')` normalisiert, bevor Pfade angehängt werden [src/c2.rs:C2Client::new].
- Nur HTTP 200 und 201 gelten als Erfolg; jeder andere Status erzeugt `C2Error::Http` mit Response-Body [src/c2.rs:ensure_ok].
- Der SMB-Relay-Zweig wird erreicht, wenn der Scan Port 445 findet — der Pfad braucht Impacket auf dem Agentenhost [src/propagate.rs:run_propagation] [../kx-scanner/src/tcp_scan.rs:COMMON_PORTS].
- Der Default-Credential-Zweig kann kein Secret liefern: `kx_exploit::try_default_credentials` gibt stets `Ok(None)` zurück [src/propagate.rs:run_propagation] [../kx-exploit/src/credential_stuff.rs:try_default_credentials].
- Der Agent verarbeitet Tasks: er holt die offenen Tasks über `GET /api/tasks`, führt
  diejenigen mit eigener Host-Kennung und Status `pending` aus und meldet Status und
  Ausgabe über `POST /api/tasks/result` zurück [src/tasks.rs:run_pending_tasks]
  [src/c2.rs:C2Client::fetch_tasks] [src/c2.rs:C2Client::report_task_result].
- Die für den ARP-Sweep verwendete MAC-Adresse ist der Platzhalter `[0x00; 6]` [src/main.rs:main].
- Der systemd-Unit wird unter unix mit allen Pflichtargumenten geschrieben (`--server`, `--token`, `--server-cert`, `--iface`, `--start`, `--end`, `--own-ip`), während `Args` `--server` und `--token` zwingend verlangt [src/main.rs:install_persistence] [../kx-posix/src/persist.rs:systemd_unit_content].
- Das Token steht nicht im Klartext in der Unit-Datei, sondern in der Environment-Datei `/etc/kx/kx-agent.env` (0600); die Unit referenziert `${KX_C2_TOKEN}` [src/main.rs:install_persistence] [../kx-posix/src/persist.rs:install_systemd_service].
- Ungültige IPs führen über `expect` zum Panic, nicht zu einem Fehlerpfad; Fehler der Secret-Extraktion werden per `unwrap_or_default()` verschluckt [src/main.rs:main] [src/main.rs:collect_local_secrets].

## Side Effects

Rollup aus [`src/`](./src/README.md):

- ARP-Sweep über `kx_scanner::arp_sweep` und TCP-Connect-Scan über `kx_scanner::scan_tcp` mit `COMMON_PORTS` und 1000 ms Timeout [src/main.rs:main] [src/propagate.rs:run_propagation].
- Lokale Secret-Extraktion über `kx_win::extract_lsass`, `kx_win::extract_credential_manager`, `kx_posix::extract_shadow_hashes`, `kx_posix::extract_aws_credentials` [src/main.rs:collect_local_secrets].
- Persistenzinstallation: `kx_win::install_service` + `kx_win::start_service` (Windows) bzw. `kx_posix::install_systemd_service` (unix), Dienstname fest `kx-agent` [src/main.rs:install_persistence].
- Netzwerk: HTTP-POST an `{base_url}/api/register`, `{base_url}/api/secrets` und
  `{base_url}/api/tasks/result`, HTTP-GET an `{base_url}/api/tasks`, jeweils mit
  `Authorization: Bearer {token}` [src/c2.rs:C2Client::register_host]
  [src/c2.rs:C2Client::upload_secret] [src/c2.rs:C2Client::fetch_tasks]
  [src/c2.rs:C2Client::report_task_result].
- Dateisystem: Lesen des Server-Zertifikats per `std::fs::read`, Auslesen des eigenen Executable-Pfads per `std::env::current_exe()`, Schreiben der Unit-Datei `/etc/systemd/system/kx-agent.service` unter unix [src/c2.rs:C2Client::new] [src/main.rs:install_persistence] [../kx-posix/src/persist.rs:install_systemd_service].
- Prozessstart: `mimikatz.exe` und `powershell.exe` unter Windows, `systemctl` unter unix, `python3 <relay_script>` im SMB-Relay-Zweig [src/main.rs:collect_local_secrets] [src/main.rs:install_persistence] [src/propagate.rs:run_propagation].
- Liest unter unix `/etc/shadow` und `$HOME/.aws/credentials` [src/main.rs:collect_local_secrets].

## Verification

- Run: `cargo test` (ausgeführt in `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` läuft grün — **59 Tests, 0 Fehler**; davon `cargo test -p kx-agent`: **3 Tests, 0 Fehler**, alle in `src/c2.rs` (`client_uses_the_contract_paths`, `register_request_serializes_host_id`, `secret_upload_carries_its_host_id`).
- Die AF_PACKET-spezifischen Teile von `kx-scanner/src/arp.rs` sind mit `#[cfg(target_os = "linux")]` ausgezeichnet; `arp_sweep` existiert in beiden Varianten und liefert außerhalb Linux `ScanError::Unsupported` statt zu kompilieren [../kx-scanner/src/arp.rs:arp_sweep].
