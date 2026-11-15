# kx-server/src

## Overview

Vollständige Implementierung des Workspace-Crates `kx-server` (C2-Backend: axum-API,
SQLite-Persistenz, Dashboard). Das Verzeichnis enthält den gesamten Rust-Code des
Crates: den axum-Server mit CLI-Flags und Routen (`main.rs`), die rusqlite-Datenschicht
(`db.rs`), die Bearer-Token-Prüfung (`auth.rs`) und das statische HTML-Dashboard
(`dashboard.rs`).

Das Crate ist ein reines Binary-Crate — es existiert kein `src/lib.rs`. Alle `pub`-Items
sind damit crate-intern und bilden keine externe Bibliothecks-API. `main.rs` deklariert
die Module `auth`, `dashboard` und `db`.

Laut Manifest (`../Cargo.toml`) deklariert das Crate `kx-core`, `kx-tls`, `serde`,
`serde_json`, `thiserror`, `tracing`, `tracing-subscriber`, `tokio`, `axum`, `axum-server`,
`rusqlite`, `time`, `clap` und `uuid`. Nachweislich verwendet werden `kx-core`
(`kx_core::c2` und `kx_core::util::now_rfc3339` [main.rs:main] [main.rs:register]),
`kx-tls` (`kx_tls::generate_server_tls` [main.rs:main]), `thiserror` [db.rs:DbError],
`tracing` [main.rs:main], `tracing-subscriber` [main.rs:main], `tokio` (`#[tokio::main]`
[main.rs:main]), `axum` (`Router` [main.rs:main]), `axum-server` [main.rs:main],
`rusqlite` [db.rs:Db::open], `clap` [main.rs:Cli] und `uuid` [main.rs:upload_secret].
`serde` und `serde_json` werden ausschließlich in den `#[cfg(test)]`-Modulen
referenziert ([dashboard.rs:keys] [db.rs:keys]); `time` wird von keiner Datei dieses
Verzeichnisses referenziert, obwohl es im Manifest deklariert ist.

Die C2-Wire-Typen und die Endpunktpfade liegen nicht in diesem Verzeichnis, sondern im
gemeinsamen Protokollmodul `kx_core::c2`. Server, Agent und CLI sprechen dieselben
Typen; die Umwandlung der Datenbankzeilen in die Wire-Typen passiert hier über
`From`-Implementierungen.

## Interface

- HTTP-Routen, registriert am `Router` in [main.rs:main]:
  - `GET /` → `dashboard` [main.rs:dashboard] — offen, liefert nur HTML
  - `POST PATH_LOGIN` → `login` [main.rs:login] — prüft das gesendete Token
  - `POST PATH_REGISTER` → `register` [main.rs:register]
  - `POST PATH_HEARTBEAT` → `heartbeat` [main.rs:heartbeat]
  - `POST PATH_SECRETS` → `upload_secret` [main.rs:upload_secret]
  - `GET PATH_HOSTS` → `list_hosts` [main.rs:list_hosts]
  - `GET PATH_SECRETS` → `list_secrets` [main.rs:list_secrets]
  - `GET PATH_TASKS` → `list_tasks` [main.rs:list_tasks]
  - `POST PATH_TASKS_CREATE` → `create_task` [main.rs:create_task]
  - `POST PATH_TASKS_RESULT` → `report_task_result` [main.rs:report_task_result]
  - Die Pfade stammen aus den Konstanten `PATH_REGISTER`, `PATH_HEARTBEAT`,
    `PATH_SECRETS`, `PATH_HOSTS`, `PATH_TASKS`, `PATH_TASKS_CREATE`,
    `PATH_TASKS_RESULT` und `PATH_LOGIN`, die aus `kx_core::c2` importiert werden
    [main.rs:main]; die wörtlichen Pfade stehen zusätzlich im Hilfetext [main.rs:HELP]
  - Die fünf Datenpfade hängen an einem eigenen API-Router mit
    `route_layer(require_auth)`; `GET /` und `POST /api/login` stehen daneben
    [main.rs:main]
- Hilfetext `HELP` — private Konstante, listet die sechs API-Endpunkte [main.rs:HELP]
- CLI-Flags (clap) [main.rs:Cli]: `--host` (`String`, Default `127.0.0.1`), `--port`
  (`u16`, Default `8443`), `--db` (`PathBuf`, Default `kx.db`), `--token`
  (`Option<String>`, Env `KX_SERVER_TOKEN`), `--cn` (`String`, Default `kx.local`)
- Request-Bodies aus `kx_core::c2`, importiert in [main.rs:main]: `RegisterRequest`
  (`host_id: String`, `ip: String`, `hostname: Option<String>`, `os: Option<String>`,
  `status: Option<String>`) [main.rs:register], `HeartbeatRequest`
  (`host_id: String`) [main.rs:heartbeat], `SecretUpload` (`host_id: String`,
  `cred_type: String`, `username: String`, `password: String`,
  `source: Option<String>`, `master_key: Option<String>`) [main.rs:upload_secret],
  `CreateTaskRequest` (`host_id: String`, `command: String`) [main.rs:create_task],
  `TaskResultRequest` (`task_id: String`, `status: String`, `result: String`)
  [main.rs:report_task_result]
- Antwort-Wire-Typen aus `kx_core::c2` [main.rs:list_hosts] [main.rs:list_secrets]
  [main.rs:list_tasks]: `c2::Host`, `c2::ExfiltratedSecret`, `c2::Task`
- Persistenztypen ohne serde — Zeilen, per Positionsindex gelesen [db.rs:HostRow]
  (`id`, `ip`, `hostname`, `os`, `status`, `first_seen`, `last_seen`),
  [db.rs:SecretRow] (`id`, `host_id`, `cred_type`, `username`, `password`, `source`,
  `collected_at`), [db.rs:TaskRow] (`id`, `host_id`, `command`, `status`, `result`,
  `created_at`)
- `DbError` — Fehler-Enum (`#[derive(Debug, thiserror::Error)]`) mit den Varianten
  `Sqlite(#[from] rusqlite::Error)` und `RowDecode` [db.rs:DbError]
- `Db` — thread-sicherer Wrapper um eine rusqlite-Connection [db.rs:Db]
  - `Db::open(path: &Path) -> Result<Self, DbError>` [db.rs:Db::open]
  - `Db::upsert_host(&self, h: &HostRow) -> Result<(), DbError>` [db.rs:Db::upsert_host]
  - `Db::list_hosts(&self) -> Result<Vec<HostRow>, DbError>` [db.rs:Db::list_hosts]
  - `Db::insert_secret(&self, s: &SecretRow) -> Result<(), DbError>` [db.rs:Db::insert_secret]
  - `Db::list_secrets(&self) -> Result<Vec<SecretRow>, DbError>` [db.rs:Db::list_secrets]
  - `Db::insert_task(&self, t: &TaskRow) -> Result<(), DbError>` [db.rs:Db::insert_task]
  - `Db::update_task_result(&self, task_id, status, result) -> Result<bool, DbError>`
    [db.rs:Db::update_task_result]
  - `Db::list_tasks(&self) -> Result<Vec<TaskRow>, DbError>` [db.rs:Db::list_tasks]
- Umwandlung Zeile → Wire-Typ [db.rs:From<HostRow> for c2::Host]
  [db.rs:From<SecretRow> for c2::ExfiltratedSecret] [db.rs:From<TaskRow> for c2::Task]
- SQL-Tabellen (DDL in [db.rs:Db::open]): `hosts` (`id TEXT PRIMARY KEY`, `ip`, `hostname`,
  `os`, `status`, `first_seen`, `last_seen`), `secrets` (`id TEXT PRIMARY KEY`, `host_id`,
  `cred_type`, `username`, `password`, `source`, `collected_at`), `tasks`
  (`id TEXT PRIMARY KEY`, `host_id`, `command`, `status`, `result`, `created_at`)
- Authentifizierung: `verify(parts: &Parts, expected: &str) -> bool` [auth.rs:verify],
  `verify_token(candidate: &str, expected: &str) -> bool` [auth.rs:verify_token] und
  die Middleware `require_auth(req: Request, next: Next) -> Response`
  [auth.rs:require_auth]
- Dashboard: `DASHBOARD_HTML` — statische HTML-Seite mit den Tabellen `#hosts`, `#secrets`
  und `#tasks` sowie dem Login-Formular `#login` [dashboard.rs:DASHBOARD_HTML]

## Invariants

- Die fünf Vertragspfade sind über eine `from_fn`-Middleware geschützt, die per
  `route_layer` auf einem eigenen API-Router hängt und danach mit dem
  Dashboard-Router gemerged wird [main.rs:main] [auth.rs:require_auth]
- Der Token-Vergleich ist constant-time (`subtle::ConstantTimeEq`); ein `==` auf
  Strings würde bei unterschiedlichem Präfix früh zurückkehren und damit
  Information über das gesuchte Token preisgeben [auth.rs:verify]
  [auth.rs:verify_token]
- Die Routen müssen **vor** dem `route_layer` registriert werden: Axum wendet
  den Layer nur auf die zum Aufrufzeitpunkt vorhandenen Routen an, eine danach
  hinzugefügte Route bliebe ungeschützt [main.rs:main]
- `route_layer` statt `layer` — sonst würde ein 404 zu einem 401 und damit
  verraten, ob ein Pfad existiert [main.rs:main]
- `verify` verlangt das Header-Präfix `Bearer ` und exakte Gleichheit des Restes mit dem
  erwarteten Token; fehlender Header, fehlendes Präfix, nicht-UTF-8-Wert und abweichender
  Token liefern alle `false` [auth.rs:verify]
- Der Login-Pfad `POST /api/login` steht **neben** dem geschützten API-Router,
  nicht darin: er prüft das Token, das er entgegennimmt, und würde sich sonst
  selbst blockieren [main.rs:login] [main.rs:main]
- Der Token wird weder im Query-String noch im stderr ausgegeben: er steht nur
  in `KX_SERVER_TOKEN` und wird vom Dashboard per Login-Formular übergeben
  [dashboard.rs:DASHBOARD_HTML] [main.rs:main]
- Das Dashboard escapet **jeden** API-Wert, bevor er in die Tabelle gesetzt wird:
  ohne Escaping wird ein im `hostname` enthaltenes `<img src=x onerror=…>` zu
  ausführbarem Markup im Browser des Operators [dashboard.rs:DASHBOARD_HTML]
- Token-Präzedenz: CLI-Flag `--token` > Umgebungsvariable `KX_SERVER_TOKEN` > zufällig
  generierte `Uuid::new_v4()` [main.rs:main]
- `std::env::set_var("KX_SERVER_TOKEN", &token)` läuft unbedingt, die Umgebungsvariable
  entspricht zur Laufzeit also immer dem effektiven Token [main.rs:main]
- Die Hinweiszeile auf stderr erscheint nur, wenn weder CLI-Flag noch Umgebungsvariable
  ein Token lieferten — clap füllt `cli.token` bereits aus `env = "KX_SERVER_TOKEN"`.
  Sie nennt **nicht** den Tokenwert [main.rs:main]
- `register` lehnt ein leeres `host_id` mit `StatusCode::BAD_REQUEST` und dem Body
  "host_id darf nicht leer sein" ab [main.rs:register]
- Die Host-ID stammt unverändert aus `req.host_id`; der Server leitet sie nicht aus der
  IP ab, sonst könnten Registrierung und Secret-Upload auseinanderlaufen
  [main.rs:register]
- Fehlende optionale Felder haben feste Defaults: `hostname` und `os` werden `""`,
  `status` wird `c2::STATUS_DISCOVERED` [main.rs:register]
- Beim Anlegen eines Hosts sind `first_seen` und `last_seen` identisch [main.rs:register]
- Ein erfolgreicher Upsert liefert `StatusCode::CREATED`, ein Datenbankfehler
  `StatusCode::INTERNAL_SERVER_ERROR` mit `e.to_string()` als Body [main.rs:register]
- Ein unbekannter `host_id` ergibt `StatusCode::NOT_FOUND`; bei einem Treffer wird nur
  `last_seen` erneuert, alle übrigen Felder werden aus der gespeicherten Zeile
  übernommen [main.rs:heartbeat]
- Der Heartbeat-Handler gibt bei einem Datenbankfehler ein nacktes
  `StatusCode::INTERNAL_SERVER_ERROR` ohne Body zurück [main.rs:heartbeat]
- `upload_secret` lehnt ein leeres `host_id` mit `StatusCode::BAD_REQUEST` und dem Body
  "host_id darf nicht leer sein" ab [main.rs:upload_secret]
- Jedes Secret erhält eine frische `Uuid::new_v4()` als ID; ein fehlendes `source` wird `""`,
  `collected_at` ist `kx_core::util::now_rfc3339()` [main.rs:upload_secret]
- Konflikt-Semantik von `upsert_host`: `ON CONFLICT(id) DO UPDATE SET last_seen=?7, os=?4,
  status=?5` — bei Konflikt bleiben `ip`, `hostname` und `first_seen` unverändert
  [db.rs:Db::upsert_host]
- Das Schema wird idempotent über `CREATE TABLE IF NOT EXISTS` angelegt; alle drei Tabellen
  deklarieren `id TEXT PRIMARY KEY` [db.rs:Db::open]
- Die einzelne rusqlite-Connection ist durch `std::sync::Mutex` geschützt; jeder Zugriff
  nimmt `self.conn.lock().unwrap()` (exklusiv, Panik bei vergiftetem Mutex) [db.rs:Db]
- `list_hosts`, `list_secrets` und `list_tasks` verwenden `SELECT` ohne `ORDER BY`, die
  Zeilenreihenfolge ist daher nicht spezifiziert [db.rs:Db::list_hosts]
  [db.rs:Db::list_secrets] [db.rs:Db::list_tasks]
- `insert_secret` und `insert_task` sind reine `INSERT`s ohne `ON CONFLICT`; eine doppelte
  Primärschlüssel-ID erzeugt `DbError::Sqlite` [db.rs:Db::insert_secret]
  [db.rs:Db::insert_task]
- `DbError::RowDecode` wird nie konstruiert — der Compiler meldet
  `variant `RowDecode` is never constructed` [db.rs:DbError]
- `create_task` schreibt über `Db::insert_task` in die Tabelle `tasks` — vorher hatte
  diese Tabelle keinen Schreibpfad, `GET /api/tasks` lieferte deshalb immer `[]`
  [db.rs:Db::insert_task] [main.rs:create_task]
- `report_task_result` schreibt Status und Ergebnis über `Db::update_task_result`
  zurück; ein UPDATE auf die Primärschlüssel-ID ist idempotent — eine wiederholte
  Meldung überschreibt denselben Wert [db.rs:Db::update_task_result]
  [main.rs:report_task_result]
- `update_task_result` liefert `false`, wenn keine Zeile mit dieser ID existierte; der
  Server antwortet dann mit 404 [db.rs:Db::update_task_result] [main.rs:report_task_result]
- Die Zeilentypen tragen keine serde-Derives und werden per Positionsindex gelesen
  (`r.get(0)?` … `r.get(6)?`), nicht über Spaltennamen [db.rs:HostRow]
  [db.rs:Db::list_hosts]
- Bei der Umwandlung Zeile → Wire-Typ wird nur das Feld `id` umbenannt, nämlich zu
  `host_id`; alle übrigen Felder behalten ihren Namen [db.rs:From<HostRow> for c2::Host]
- Das Task-Feld auf dem Draht heißt `result` — es existiert kein `output` in der
  Umwandlung, und der Server sendet `result` [db.rs:From<TaskRow> for c2::Task]
- Die Bind-Adresse wird über `to_socket_addrs()` aufgelöst und nur die erste Adresse
  verwendet (`.next()`); ein Auflösungsfehler bricht den Prozess ab [main.rs:main]
- Das Dashboard-HTML wird ohne Authentifizierung ausgeliefert — es enthält keine
  Geheimnisse. Das Token erreicht den Browser über das Login-Formular `#login`,
  das es an `POST /api/login` schickt; die Daten holt sich das Skript danach per
  `fetch` mit `Authorization`-Header [main.rs:dashboard] [dashboard.rs:DASHBOARD_HTML]
- Das Dashboard-JavaScript ruft genau drei Endpunkte ab und liest genau die Felder
  `h.ip`, `h.hostname`, `h.os`, `h.status`; `s.host_id`, `s.cred_type`, `s.username`,
  `s.password`, `s.source`; `t.host_id`, `t.command`, `t.status`, `t.result`
  [dashboard.rs:DASHBOARD_HTML]
- Der Dashboard-Request trägt den Header `Authorization: Bearer <TOKEN>`; bei einer
  nicht erfolgreichen Antwort ersetzt das Skript den Tabellenkörper durch den Text
  "Auth fehlgeschlagen" [dashboard.rs:DASHBOARD_HTML]

## Side Effects

- Öffnet bzw. legt die SQLite-Datenbankdatei am Pfad aus `--db` an (Default `kx.db`,
  relativ zum Arbeitsverzeichnis des Prozesses) [db.rs:Db::open]
- Führt das Schema-DDL per `conn.execute_batch` aus: `CREATE TABLE IF NOT EXISTS hosts (...)`,
  `CREATE TABLE IF NOT EXISTS secrets (...)`, `CREATE TABLE IF NOT EXISTS tasks (...)`
  [db.rs:Db::open]
- SQL-Schreibzugriffe: `INSERT INTO hosts (...) ... ON CONFLICT(id) DO UPDATE SET ...`
  [db.rs:Db::upsert_host], `INSERT INTO secrets (...)` [db.rs:Db::insert_secret],
  `INSERT INTO tasks (...)` [db.rs:Db::insert_task] und `UPDATE tasks SET status, result
  WHERE id` [db.rs:Db::update_task_result]
- SQL-Lesezugriffe: `SELECT id, ip, hostname, os, status, first_seen, last_seen FROM hosts`
  [db.rs:Db::list_hosts], `SELECT id, host_id, cred_type, username, password, source,
  collected_at FROM secrets` [db.rs:Db::list_secrets], `SELECT id, host_id, command, status,
  result, created_at FROM tasks` [db.rs:Db::list_tasks]
- Schreibt die Umgebungsvariable `KX_SERVER_TOKEN` prozessweit [main.rs:main]
- Initialisiert den globalen tracing-Subscriber; ohne `RUST_LOG` filtert er auf `kx_server=info`
  [main.rs:main]
- Schreibt eine Hinweiszeile nach stderr, wenn kein Token vorgegeben wurde — **ohne**
  den Tokenwert zu nennen; er steht in `KX_SERVER_TOKEN` [main.rs:main]
- Loggt die Bind-Adresse und die API-Übersicht auf INFO-Level [main.rs:main]
- Erzeugt ein selbstsigniertes TLS-Zertifikat und einen Schlüssel im Speicher (CN aus `--cn`);
  es wird keine Zertifikatsdatei geschrieben [main.rs:main]
- Startet einen TLS-Listener (`axum_server::bind_rustls`) auf `host:port` (Default
  `127.0.0.1:8443`) [main.rs:main]
- Liest die Umgebungsvariable `KX_SERVER_TOKEN` zur Token-Prüfung
  [auth.rs:require_auth] [main.rs:login]
- Das Dashboard liest das Token **nicht** aus dem URL-Query-Parameter, sondern
  aus dem Login-Formular und sendet es als `Authorization: Bearer`-Header an
  `/api/hosts`, `/api/secrets` und `/api/tasks`; die Antworten werden per
  `innerHTML` in die Tabellen geschrieben, wobei **jeder Wert** vorher durch
  `esc()` escapt wird [dashboard.rs:DASHBOARD_HTML]

## Verification

- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` läuft grün — 59 Tests, 0 Fehler. Davon entfallen 13 auf
  dieses Crate: 3 in [db.rs:tests] (`host_row_maps_to_wire_host`,
  `task_row_maps_result_field`, `secret_row_maps_to_wire_secret`), 4 in [main.rs:tests]
  (`help_text_lists_every_contract_path`, `router_registers_the_contract_paths`,
  `api_paths_require_a_valid_bearer_token`, `unknown_path_is_404_not_401`,
  `login_path_checks_the_token_it_receives`) und 6 in
  [dashboard.rs:tests] (`dashboard_endpoints_are_the_contract_paths`,
  `dashboard_reads_only_fields_the_contract_defines`,
  `dashboard_reads_the_task_result_field`,
  `dashboard_escapes_every_api_value`,
  `dashboard_does_not_read_the_token_from_the_url`)
