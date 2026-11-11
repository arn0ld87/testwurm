# kx-server

## Overview

Rust-Binärcrate `kx-server` (Version 0.1.0, Edition 2021, MSRV 1.77, Lizenz MIT) im
Kx-Workspace. Das Manifest [Cargo.toml](./Cargo.toml) beschreibt das C2-Backend
(`Kx-C2-Server: Host-Registry, Secret-Store, Dashboard`) und deklariert die
Abhängigkeiten `kx-core`, `kx-tls`, `serde`, `serde_json`, `thiserror`, `tracing`,
`tracing-subscriber`, `tokio`, `axum`, `axum-server`, `rusqlite`, `time`, `clap` und
`uuid`.

Dieses Verzeichnis enthält keine direkten Quelldateien; der gesamte Rust-Code liegt in
`src/`. Das Crate ist binär-only — es existiert kein `src/lib.rs`, daher bilden die
`pub`-Items in `src/` keine externe Bibliotheks-API. Die beiden Workspace-Crates
`kx-core` (`kx_core::c2`, `kx_core::util::now_rfc3339`) und `kx-tls`
(`kx_tls::generate_server_tls`) sind die einzigen lokalen Crates, die im Code tatsächlich
verwendet werden; `serde` und `serde_json` werden ausschließlich in den Testmodulen
referenziert, `time` wird von keiner Datei referenziert.

Die Verifikation erfolgt über `cargo test` aus der Workspace-Wurzel
`/Volumes/T7/Projekte/testwurm/kx`.

## Subdirectories & Boundaries

- [src](./src/README.md) - TLS-gesicherter axum-Server mit Routen für Host-Registry,
  Heartbeat und Secret-Upload (`main.rs`), SQLite-Persistenz (`db.rs`),
  Bearer-Token-Prüfung (`auth.rs`) und statisches HTML-Dashboard (`dashboard.rs`).

## Interface

Rollup aus [`src/`](./src/README.md):

- API-Routen, registriert am `Router` [src/main.rs:main]: `GET /` → `dashboard`
  [src/main.rs:dashboard], `POST PATH_REGISTER` → `register` [src/main.rs:register],
  `POST PATH_HEARTBEAT` → `heartbeat` [src/main.rs:heartbeat], `POST PATH_SECRETS` →
  `upload_secret` [src/main.rs:upload_secret], `GET PATH_HOSTS` → `list_hosts`
  [src/main.rs:list_hosts], `GET PATH_SECRETS` → `list_secrets`
  [src/main.rs:list_secrets], `GET PATH_TASKS` → `list_tasks` [src/main.rs:list_tasks].
  Die Pfade stammen aus den Konstanten `PATH_REGISTER`, `PATH_HEARTBEAT`, `PATH_SECRETS`,
  `PATH_HOSTS` und `PATH_TASKS` in `kx_core::c2` [src/main.rs:main].
- CLI-Flags `--host` (Default `127.0.0.1`), `--port` (Default `8443`), `--db` (Default
  `kx.db`), `--token` (Env `KX_SERVER_TOKEN`), `--cn` (Default `kx.local`)
  [src/main.rs:Cli].
- Request-Typen aus dem gemeinsamen Protokollmodul `kx_core::c2`: `RegisterRequest`
  [src/main.rs:register], `HeartbeatRequest` [src/main.rs:heartbeat], `SecretUpload`
  [src/main.rs:upload_secret]; Antwort-Typen `c2::Host` [src/main.rs:list_hosts],
  `c2::ExfiltratedSecret` [src/main.rs:list_secrets], `c2::Task` [src/main.rs:list_tasks].
- `pub struct Db` mit `open`, `upsert_host`, `list_hosts`, `insert_secret`, `list_secrets`,
  `insert_task`, `list_tasks`; Datenmodelle `HostRow`, `SecretRow`, `TaskRow`
  [src/db.rs:Db] [src/db.rs:Db::open] [src/db.rs:HostRow] [src/db.rs:SecretRow]
  [src/db.rs:TaskRow].
- SQL-Tabellen `hosts`, `secrets`, `tasks` — jeweils `id TEXT PRIMARY KEY`
  [src/db.rs:Db::open].
- `pub fn verify(parts, expected) -> bool`, `pub fn verify_token(candidate, expected) -> bool`
  und die Middleware `pub async fn require_auth(req, next) -> Response`
  [src/auth.rs:verify] [src/auth.rs:verify_token] [src/auth.rs:require_auth].
- `DASHBOARD_HTML` — statische HTML-Konstante mit den Tabellen `#hosts`, `#secrets`,
  `#tasks` und dem Login-Formular `#login` [src/dashboard.rs:DASHBOARD_HTML].

## Invariants

Rollup aus [`src/`](./src/README.md):

- **Die fünf Vertragspfade sind authentifiziert.** Sie hängen an einem eigenen
  API-Router mit `route_layer(require_auth)`; der Vergleich ist constant-time
  [src/main.rs:main] [src/auth.rs:require_auth] [src/auth.rs:verify].
- `verify` akzeptiert nur einen `Authorization`-Header mit dem Präfix `Bearer ` und exakt
  passendem Token; fehlender Header, fehlendes Präfix, nicht-UTF-8-Wert und abweichender
  Token liefern alle `false` [src/auth.rs:verify].
- Token-Präzedenz: CLI-Flag `--token` > Umgebungsvariable `KX_SERVER_TOKEN` > zufällig
  generierte `Uuid::new_v4()` [src/main.rs:main].
- Der Host-Handler setzt `id: req.host_id` und lehnt ein leeres `host_id` mit
  `StatusCode::BAD_REQUEST` ab; die Host-ID wird nicht aus der IP abgeleitet
  [src/main.rs:register] [src/main.rs:upload_secret].
- `upsert_host` nutzt `ON CONFLICT(id) DO UPDATE SET last_seen, os, status` — bei Konflikt
  bleiben `ip`, `hostname` und `first_seen` unverändert [src/db.rs:Db::upsert_host].
- Die Zeilentypen tragen keine serde-Derives und werden per Positionsindex gelesen; die
  Umwandlung in die Wire-Typen passiert über `From<HostRow> for c2::Host`,
  `From<SecretRow> for c2::ExfiltratedSecret` und `From<TaskRow> for c2::Task`, wobei nur
  `id` zu `host_id` umbenannt wird [src/db.rs:HostRow] [src/db.rs:From<HostRow> for c2::Host].
- Das Schema wird idempotent über `CREATE TABLE IF NOT EXISTS` angelegt; die einzelne
  rusqlite-Connection ist durch einen `Mutex` geschützt [src/db.rs:Db::open]
  [src/db.rs:Db].
- `list_hosts`, `list_secrets` und `list_tasks` verwenden `SELECT` ohne `ORDER BY` — die
  Zeilenreihenfolge ist nicht spezifiziert [src/db.rs:Db::list_hosts].
- `Db::insert_task` wird von keinem Handler aufgerufen; `GET /api/tasks` liefert deshalb
  ein leeres Array [src/db.rs:Db::insert_task] [src/main.rs:list_tasks].
- Der Server bindet nur die erste per `to_socket_addrs()` aufgelöste Adresse
  [src/main.rs:main].

## Side Effects

Rollup aus [`src/`](./src/README.md):

- Dateisystem: `Connection::open` legt die SQLite-Datenbankdatei unter dem `--db`-Pfad
  an; das DDL `CREATE TABLE IF NOT EXISTS` für `hosts`, `secrets` und `tasks` wird per
  `execute_batch` ausgeführt [src/db.rs:Db::open].
- SQL-DML: `INSERT INTO hosts ... ON CONFLICT`, `INSERT INTO secrets`, `INSERT INTO tasks`
  sowie die drei `SELECT`-Abfragen [src/db.rs:Db::upsert_host]
  [src/db.rs:Db::insert_secret] [src/db.rs:Db::insert_task].
- Prozesszustand: `std::env::set_var("KX_SERVER_TOKEN", &token)` setzt die
  Umgebungsvariable unbedingt [src/main.rs:main].
- Schreibt das effektive Bearer-Token im Klartext nach stderr, wenn kein Token vorgegeben
  wurde [src/main.rs:main].
- Erzeugt ein selbstsigniertes TLS-Zertifikat und einen Schlüssel im Speicher; es wird
  **keine** Zertifikatsdatei geschrieben [src/main.rs:main].
- Startet einen TLS-Listener (`axum_server::bind_rustls`) auf `host:port`
  [src/main.rs:main].
- Das Dashboard liest das Token aus dem URL-Query-Parameter `token` und sendet es als
  `Authorization: Bearer`-Header an `/api/hosts`, `/api/secrets` und `/api/tasks`
  [src/dashboard.rs:DASHBOARD_HTML].

## Verification

- Run: `cargo test` (ausgeführt in `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` läuft grün — 59 Tests, 0 Fehler, davon 13 aus diesem
  Crate (`db.rs`, `main.rs`, `dashboard.rs`).
