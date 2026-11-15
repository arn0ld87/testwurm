//! Asynchroner TCP-Connect-Portscan mit tokio.
//!
//! Verbindet parallel zu allen Hosts/Ports und meldet offene Ports.
//! Nutzt die Connect-Methode (kein SYN-Sweep), daher sichtbarer für Firewalls.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::debug;

/// Ergebnisse eines TCP-Scans.
#[derive(Debug, Clone, Default)]
pub struct ScanResults {
    /// Offene Ports pro Host.
    pub open_ports: std::collections::HashMap<IpAddr, Vec<u16>>,
}

impl ScanResults {
    /// Erzeuge eine leere Ergebnis-Struktur.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Standard-Ports für häufige Dienste.
pub const COMMON_PORTS: &[u16] = &[
    22,   // SSH
    80,   // HTTP
    135,  // RPC
    445,  // SMB (Werm-Propagation)
    443,  // HTTPS
    1433, // SQL Server
    1521, // Oracle
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    5900, // VNC
    8080, // HTTP-Proxy
];

/// Scanne parallel TCP-Ports auf den angegebenen Hosts.
///
/// # Parameter
/// - `hosts`: IP-Adressen der Ziele
/// - `ports`: Zu scannende Ports
/// - `timeout`: Verbindungstimeout pro Port
///
/// # Rückgabe
/// Ergebnis mit offenen Ports pro Host.
pub async fn scan_tcp(hosts: &[IpAddr], ports: &[u16], timeout_ms: u64) -> ScanResults {
    let mut results = ScanResults::new();
    let conn_timeout = Duration::from_millis(timeout_ms);

    let mut handles = Vec::new();
    for host in hosts {
        for port in ports {
            let host = *host;
            let port = *port;
            handles.push(tokio::spawn(async move {
                let addr = SocketAddr::new(host, port);
                match tokio::time::timeout(conn_timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_stream)) => (host, port, true),
                    _ => (host, port, false),
                }
            }));
        }
    }

    for handle in handles {
        if let Ok((host, port, open)) = handle.await {
            if open {
                debug!("Offener Port: {}:{}", host, port);
                results.open_ports.entry(host).or_default().push(port);
            }
        }
    }
    results
}

/// Scanne nur die häufigsten Ports (schneller).
pub async fn scan_common_ports(hosts: &[IpAddr], timeout_ms: u64) -> ScanResults {
    scan_tcp(hosts, COMMON_PORTS, timeout_ms).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    /// Die Scanliste enthält SMB und RDP — ohne 445 ist der SMB-Relay-Zweig
    /// des Agenten toter Code.
    ///
    /// 445 selbst lässt sich im Test nicht binden (privilegierter Port, dafür
    /// wären Root-Rechte nötig), deshalb wird die Liste geprüft und der Scan
    /// an einem freien Port nachgewiesen.
    #[test]
    fn die_scanliste_enthaelt_smb_und_rdp() {
        assert!(
            COMMON_PORTS.contains(&445),
            "SMB (445) fehlt in der Scanliste"
        );
        assert!(
            COMMON_PORTS.contains(&3389),
            "RDP (3389) fehlt in der Scanliste"
        );
    }

    /// Der Scan meldet einen offenen Port im Ergebnis.
    #[tokio::test]
    async fn der_scan_meldet_einen_offenen_port() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Listener öffnet");
        let port = listener.local_addr().expect("Adresse").port();
        tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ergebnis = scan_tcp(&[host], &[port], 500).await;

        let offene = ergebnis
            .open_ports
            .get(&host)
            .expect("Ergebnis für den Host");
        assert!(
            offene.contains(&port),
            "der offene Port {port} fehlt im Ergebnis: {offene:?}"
        );
    }
}
