//! Asynchroner TCP-Connect-Portscan mit tokio.
//!
//! Verbindet parallel zu allen Hosts/Ports und meldet offene Ports.
//! Nutzt die Connect-Methode (kein SYN-Sweep), daher sichtbarer für Firewalls.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::debug;

/// Ergebnisse eines TCP-Scans.
#[derive(Debug, Clone)]
pub struct ScanResults {
    /// Offene Ports pro Host.
    pub open_ports: std::collections::HashMap<IpAddr, Vec<u16>>,
}

impl ScanResults {
    /// Erzeuge eine leere Ergebnis-Struktur.
    pub fn new() -> Self {
        Self { open_ports: std::collections::HashMap::new() }
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
