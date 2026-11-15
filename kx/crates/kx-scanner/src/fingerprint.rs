//! OS- und Dienst-Fingerprinting via Banner-Grepping.
//!
//! Verbindet sich zu entdeckten Diensten und analysiert die Banner,
//! um Betriebssystem und Dienstversion zu bestimmen.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// Informationen über einen entdeckten Dienst.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// IP-Adresse des Hosts.
    pub host: std::net::IpAddr,
    /// Port des Dienstes.
    pub port: u16,
    /// Dienstekennung (z.B. "smb", "ssh", "http").
    pub service: String,
    /// Version des Dienstes, falls erkannt.
    pub version: Option<String>,
    /// Betriebssystem-Schätzung, falls erkannt.
    pub os: Option<String>,
    /// Rohes Banner für weitere Analyse.
    pub banner: String,
}

impl ServiceInfo {
    /// Erzeuge eine neue ServiceInfo-Struktur.
    pub fn new(host: std::net::IpAddr, port: u16, service: String) -> Self {
        Self {
            host,
            port,
            service,
            version: None,
            os: None,
            banner: String::new(),
        }
    }
}

/// Greife das Banner eines TCP-Dienstes ab.
async fn grab_banner(addr: SocketAddr, timeout_ms: u64) -> Result<String, ()> {
    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let mut stream = stream;
    let mut buf = [0u8; 1024];
    match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Ok(String::from_utf8_lossy(&buf[..n]).to_string()),
        _ => Err(()),
    }
}

/// Identifiziere den Dienst anhand des Ports.
pub fn identify_service(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        80 => "http",
        135 => "msrpc",
        443 => "https",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        5432 => "postgresql",
        5900 => "vnc",
        8080 => "http-proxy",
        _ => "unknown",
    }
}

/// Führe Fingerprinting für einen entdeckten Dienst durch.
///
/// # Parameter
/// - `host`: IP des Ziels
/// - `port`: Port des Dienstes
/// - `timeout_ms`: Timeout für die Verbindung
///
/// # Rückgabe
/// ServiceInfo mit OS- und Versionsinformationen, falls erkannt.
pub async fn fingerprint(
    host: std::net::IpAddr,
    port: u16,
    timeout_ms: u64,
) -> Option<ServiceInfo> {
    let addr = SocketAddr::new(host, port);
    let banner = match grab_banner(addr, timeout_ms).await {
        Ok(b) => b,
        Err(_) => return None,
    };

    let service = identify_service(port).to_string();
    let mut info = ServiceInfo::new(host, port, service);
    info.banner = banner.clone();

    // Einfache Pattern-Erkennung
    if banner.contains("SSH-") {
        info.version = banner.split_whitespace().next().map(|s| s.to_string());
        if banner.contains("OpenSSH") {
            info.os = Some("Linux/Unix".to_string());
        }
    } else if banner.contains("Microsoft") || banner.contains("Windows") {
        info.os = Some("Windows".to_string());
    }

    debug!("Fingerprint für {}:{}", host, port);
    Some(info)
}
