# kx-cli src

## Overview

Quellcode des Rust-Binärcrates `kx-cli` — die Operator-Oberfläche des Kx-C2-Servers. Das Crate besitzt keine `lib.rs`; `main.rs` ist der einzige Crate-Einstiegspunkt, und `mod client;` [main.rs:mod client] deklariert `client.rs` als privates Modul. Alle `pub`-Items in `client.rs` sind damit crate-intern und bilden keine nach außen exportierte Bibliotheks-API.

`main.rs` definiert die clap-Oberfläche (`Cli`, `Command`) und dispatcht die Unterbefehle; `client.rs` kapselt den TLS-gesicherten HTTP-Zugriff (`Client`, `get_json`) sowie den Dateiexport (`export`). Die drei `Client`-Methoden sind als `async fn` deklariert, führen aber jeweils einen blockierenden `ureq`-Aufruf ohne `.await` innerhalb des von `#[tokio::main]` [main.rs:main] gestarteten Tokio-Runtimes aus.

Die Datenmodelle stammen aus `kx_core::c2` — derselben Quelle der Wahrheit, die auch der C2-Server verwendet. `client.rs` importiert `ExfiltratedSecret`, `Host` und `Task` sowie die Pfadkonstanten `PATH_HOSTS`, `PATH_SECRETS` und `PATH_TASKS` [client.rs:Client::hosts] [client.rs:Client::secrets] [client.rs:Client::tasks]; ein eigener Typ `Secret` existiert im Crate nicht. Der einzige Zugriff auf `kx-tls` ist `kx_tls::client_config_trusting(&cert_pem)` [client.rs:Client::new].

## Interface

### CLI

- [main.rs:Cli] — `#[derive(Parser)]`, `#[command(name = "kx-cli", about = "Kx-Operator-Oberfläche")]`; die Binärdatei wird als `kx-cli` aufgerufen.
- [main.rs:Cli.server] — Top-Level-Argument `--server` mit Env-Fallback `KX_C2_URL`; Pflichtangabe, Doc: „URL des C2-Servers (https://host:port)“.
- [main.rs:Cli.token] — Top-Level-Argument `--token` mit Env-Fallback `KX_C2_TOKEN`; Pflichtangabe, Doc: „Bearer-Token für den C2-Server“.
- [main.rs:Cli.cert] — Top-Level-Argument `--cert` ohne Env-Fallback; Pflichtangabe, Doc: „Pfad zum Server-Zertifikat (PEM)“.
- [main.rs:Command::Hosts] — Subcommand `hosts`, keine Flags.
- [main.rs:Command::Secrets] — Subcommand `secrets` mit Flag `--user` (`Option<String>`, Doc: „Optionaler Filter nach Benutzername (Teilstring)“).
- [main.rs:Command::Export] — Subcommand `export` mit positionellem Argument `path: PathBuf` und Flag `--format` (`default_value = "json"`).
- [main.rs:Command::Tasks] — Subcommand `tasks`, keine Flags.

### Client-API (crate-intern)

- [client.rs:ApiError] — `pub enum ApiError` mit den Varianten `Tls(String)`, `Http(String)`, `Json(String)`, `Io(String)`.
- [client.rs:Client] — `pub struct Client` mit privaten Feldern `agent: ureq::Agent`, `base_url: String`, `token: String`.
- [client.rs:Client::new] — `pub fn new(server: &str, token: &str, cert: &str) -> Result<Self, ApiError>`.
- [client.rs:Client::hosts] — `pub async fn hosts(&self) -> Result<Vec<Host>, ApiError>`; HTTP GET auf `{base_url}{PATH_HOSTS}`.
- [client.rs:Client::secrets] — `pub async fn secrets(&self) -> Result<Vec<ExfiltratedSecret>, ApiError>`; HTTP GET auf `{base_url}{PATH_SECRETS}`.
- [client.rs:Client::tasks] — `pub async fn tasks(&self) -> Result<Vec<Task>, ApiError>`; HTTP GET auf `{base_url}{PATH_TASKS}`.
- [client.rs:export] — `pub fn export(secrets: &[ExfiltratedSecret], path: &Path, format: &str) -> Result<(), ApiError>`; exportiert als JSON oder CSV.
- [client.rs:get_json] — modulprivater generischer Helper `fn get_json<T: for<'de> Deserialize<'de>>(agent: &Agent, url: &str, token: &str) -> Result<T, ApiError>`.

### Protokolltypen (aus `kx_core::c2`)

- [kx-core/src/c2.rs:Host](../../kx-core/src/c2.rs) — `pub struct Host`, Felder `host_id`, `ip`, `hostname`, `os`, `status`, `first_seen`, `last_seen` (alle `String`); trägt `#[serde(deny_unknown_fields)]`.
- [kx-core/src/c2.rs:ExfiltratedSecret](../../kx-core/src/c2.rs) — `pub struct ExfiltratedSecret`, Felder `id`, `host_id`, `cred_type`, `username`, `password`, `source`, `collected_at` (alle `String`); trägt `#[serde(deny_unknown_fields)]`.
- [kx-core/src/c2.rs:Task](../../kx-core/src/c2.rs) — `pub struct Task`, Felder `id`, `host_id`, `command`, `status`, `result: String` (verpflichtend, nicht optional) und `created_at`; trägt `#[serde(deny_unknown_fields)]`.
- [kx-core/src/c2.rs:PATH_HOSTS](../../kx-core/src/c2.rs) — `pub const PATH_HOSTS: &str = "/api/hosts"`.
- [kx-core/src/c2.rs:PATH_SECRETS](../../kx-core/src/c2.rs) — `pub const PATH_SECRETS: &str = "/api/secrets"`.
- [kx-core/src/c2.rs:PATH_TASKS](../../kx-core/src/c2.rs) — `pub const PATH_TASKS: &str = "/api/tasks"`.

### Tests

- [client.rs:tests::export_writes_csv] — schreibt eine Zeile in eine CSV-Datei im Temp-Verzeichnis und prüft, dass der Benutzername enthalten ist.
- [client.rs:tests::cli_reads_the_task_result_from_server_json] — Regressionstest: das Server-JSON mit dem Feld `result` muss in `Vec<Task>` deserialisieren; prüft `tasks[0].result`.
- [client.rs:tests::cli_reads_hosts_and_secrets_from_server_json] — Regressionstest: Host- und Secret-JSON des Servers müssen lesbar sein; prüft `host_id`, `status` und `cred_type`.

## Invariants

- [main.rs:mod client] — Die Crate ist binary-only; es existiert keine `lib.rs`, daher bilden alle `pub`-Items keine exportierte Bibliotheks-API.
- [main.rs:Cli.server] — Die drei Top-Level-Argumente sind **keine** clap-`global`-Flags (`global = true` fehlt); sie müssen vor dem Subcommand stehen. `kx-cli hosts --server https://x` scheitert mit „unexpected argument '--server' found“.
- [main.rs:Cli.token] — `--server` und `--token` besitzen einen Env-Fallback (`KX_C2_URL`, `KX_C2_TOKEN`), `--cert` besitzt keinen; alle drei sind Pflichtangaben.
- [main.rs:Command::Export] — `--format` hat den Default-Wert `"json"`; der Wert ist ein freier String und wird nicht gegen eine Liste validiert.
- [kx-core/src/c2.rs:Host](../../kx-core/src/c2.rs) — Die drei Wire-Typen tragen `#[serde(deny_unknown_fields)]`; jedes unbekannte Feld im Server-JSON bricht die Deserialisierung ab und wird über `serde_json::from_str` zu `ApiError::Json` [client.rs:get_json].
- [kx-core/src/c2.rs:Host](../../kx-core/src/c2.rs) — Der Identifikator des Hosts heißt `host_id` (nicht `id`); die CLI liest und schreibt genau dieses Feld [client.rs:export].
- [kx-core/src/c2.rs:Task](../../kx-core/src/c2.rs) — `Task::result` ist ein verpflichtendes `String`-Feld, kein `Option`; leer bedeutet „Task noch nicht ausgeführt“. Ein optionales Feld existiert nicht.
- [kx-core/src/c2.rs:ExfiltratedSecret](../../kx-core/src/c2.rs) — `host_id` verweist laut Typ-Doc auf `Host::host_id` und darf nicht leer sein; die CLI selbst validiert das nicht.
- [client.rs:Client::new] — `base_url` normalisiert den Serverwert über `server.trim_end_matches('/')`; alle abschließenden `/` werden entfernt, bevor Pfade angehängt werden.
- [client.rs:get_json] — Der Auth-Header ist exakt `Authorization: Bearer {token}`; Query-Parameter werden nie angehängt.
- [client.rs:export] — Die Formatierung verzweigt auf ein exaktes Match gegen das Literal `"csv"`; jeder andere Wert (einschließlich `"json"` und unbekannter Strings) fällt in den `_`-Zweig und wird als Pretty-JSON serialisiert.
- [client.rs:export] — Die CSV-Kopfzeile lautet exakt `host_id,cred_type,username,password,source,collected_at`; die Datenzeilen folgen derselben Spaltenreihenfolge, `ExfiltratedSecret.id` wird im CSV nicht ausgegeben.
- [client.rs:export] — Der JSON-Zweig serialisiert das vollständige `Vec<ExfiltratedSecret>` (alle Felder inklusive `id` und `password`) via `serde_json::to_writer_pretty`.
- [client.rs:export] — Fehler beim Anlegen der Datei sowie bei jedem Schreibvorgang werden zu `ApiError::Io`.
- [kx-tls/src/lib.rs:client_config_trusting](../../kx-tls/src/lib.rs) — Das TLS-Vertrauen ist auf exakt die im `--cert`-PEM enthaltenen Zertifikate gepinnt; der Root-Store startet leer, es wird kein Client-Zertifikat präsentiert.
- [main.rs:Command::Secrets] — Der Filter `--user` ist ein Substring-Test auf `s.username`; ohne `--user` bleiben alle Secrets erhalten.
- [main.rs:main] — Jeder Fehlerpfad beendet den Prozess mit Exit-Code 1: Client-Init, Host-Abfrage, Secret-Abfrage, Export und Task-Abfrage. Argumentationsfehler von clap beenden dagegen mit **Exit-Code 2** (`Cli::parse()` in `main.rs:61`), `--help` endet mit 0.
- [main.rs:main] — Der Logfilter fällt auf `"info"` zurück, wenn `tracing_subscriber::EnvFilter::try_from_default_env()` fehlschlägt (also `RUST_LOG` fehlt oder unparsbar ist).
- [main.rs:main] — Die stdout-Zeilenformate sind fest: Hosts `{:<15} {:<20} {:<15} {}` über `ip, hostname, os, status`; Secrets `{:<20} {:<30} {:<15} {}` über `cred_type, username, source, collected_at`; Tasks `{:<36} {:<20} {}` über `id, status, created_at`.
- [main.rs:main] — `export` filtert nicht: die Bestätigung meldet die Anzahl aller abgerufenen Secrets, unabhängig von `--user` (das der Subcommand `export` gar nicht kennt).

## Side Effects

- [client.rs:Client::new] — Dateisystem-Leszugriff: `std::fs::read(cert)` liest die PEM-Datei des `--cert`-Pfads bei jeder Client-Konstruktion.
- [client.rs:Client::new] — TLS-Aufbau: `ureq::AgentBuilder::new().tls_config(client_config).build()` erzeugt einen `ureq::Agent`, der ausschließlich dem übergebenen Zertifikat vertraut.
- [client.rs:Client::hosts] — Netzwerk: HTTP GET auf `{base_url}/api/hosts` mit Header `Authorization: Bearer {token}`.
- [client.rs:Client::secrets] — Netzwerk: HTTP GET auf `{base_url}/api/secrets` mit Header `Authorization: Bearer {token}`.
- [client.rs:Client::tasks] — Netzwerk: HTTP GET auf `{base_url}/api/tasks` mit Header `Authorization: Bearer {token}`.
- [client.rs:export] — Dateisystem-Schreibzugriff: `std::fs::File::create(path)` legt die Exportdatei an oder überschreibt sie; das Anlegen erfolgt in beiden Zweigen vor dem verzweigungsspezifischen Schreiben.
- [client.rs:export] — Dateisystem-Schreibzugriff (CSV-Zweig): Kopfzeile `host_id,cred_type,username,password,source,collected_at` gefolgt von einer Zeile pro Secret im Klartext, einschließlich `password`.
- [client.rs:export] — Dateisystem-Schreibzugriff (JSON-Zweig): `serde_json::to_writer_pretty(&mut file, secrets)` schreibt das vollständige `Vec<ExfiltratedSecret>` als formatiertes JSON, einschließlich `id` und `password`.
- [main.rs:main] — stdout-Schreibzugriffe: `println!` pro Host (`ip, hostname, os, status`), pro Secret (`cred_type, username, source, collected_at` — das Passwort wird nicht ausgegeben) und pro Task (`id, status, created_at`).
- [main.rs:main] — Prozessabbruch: `std::process::exit(1)` bei Client-Init-Fehler sowie bei fehlgeschlagener Host-, Secret-, Export- und Task-Abfrage.
- [main.rs:main] — Globaler Zustand: `tracing_subscriber::fmt().with_env_filter(...).init()` installiert den globalen Tracing-Subscriber; `info!` meldet Ergebnisanzahlen und Exportbestätigung, `error!` jeden Fehler.
- [main.rs:main] — Der Client wird vor dem Subcommand-Dispatch unbedingt konstruiert, sodass die Zertifikatsdatei bei jedem Aufruf gelesen und der TLS-Agent aufgebaut wird — auch beim reinen Export.
- [client.rs:tests::export_writes_csv] — Test-only: `export` schreibt `kx-cli-test.csv` in `std::env::temp_dir()`, die Datei wird mit `std::fs::read_to_string` zurückgelesen und mit `std::fs::remove_file` entfernt.

## Verification

- Run: `cd /Volumes/T7/Projekte/testwurm/kx && cargo test`
- Stand: `cargo test --workspace` läuft grün — 59 Tests, 0 Fehler, davon 3 in `kx-cli` (`export_writes_csv`, `cli_reads_the_task_result_from_server_json`, `cli_reads_hosts_and_secrets_from_server_json`).
