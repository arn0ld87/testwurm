//! Kx-Scanner: Netzwerkerkennung und Service-Fingerprinting.
//!
//! Diese Crate bietet Module zur Entdeckung von Hosts und Diensten im Netzwerk:
//! - `arp`: ARP-Sweep für Layer-2-Entdeckung
//! - `tcp_scan`: Asynchroner TCP-Connect-Portscan
//! - `fingerprint`: OS/Dienst-Fingerprinting via Banner-Analyse

pub mod arp;
pub mod error;
pub mod fingerprint;
pub mod range;
pub mod tcp_scan;

pub use arp::{arp_sweep, read_mac, DiscoveredHost};
pub use error::ScanError;
pub use fingerprint::{fingerprint, ServiceInfo};
pub use range::{bereich_ist_zu_gross, ip_range};
pub use tcp_scan::{scan_common_ports, scan_tcp, ScanResults, COMMON_PORTS};
