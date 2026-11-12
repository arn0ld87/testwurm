//! ARP-Sweep zur Layer-2-Entdeckung von Hosts im lokalen Netz.
//!
//! Nutzt AF_PACKET-Raw-Sockets (Linux) zum Senden von ARP-Broadcast-Anfragen
//! und zum Empfangen der Antworten. Erfordert CAP_NET_RAW oder Root-Rechte.
//!
//! Der Sweep ist Linux-only. Auf anderen Plattformen liefert `arp_sweep` einen
//! Fehler — so wie `kx-win` und `kx-posix` ihre Plattformgrenzen ziehen.

use std::net::IpAddr;

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::mem;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
use libc::{c_void, sockaddr_ll};
#[cfg(target_os = "linux")]
use tracing::debug;

use crate::error::ScanError;

/// Entdeckter Host mit MAC- und IP-Adresse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    /// MAC-Adresse des Hosts.
    pub mac: [u8; 6],
    /// IP-Adresse des Hosts.
    pub ip: IpAddr,
}

/// Erstelle einen AF_PACKET-Socket für ARP-Scans auf dem angegebenen Interface.
#[cfg(target_os = "linux")]
fn create_arp_socket(iface: &str) -> Result<RawFd, ScanError> {
    unsafe {
        let sock = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        );
        if sock < 0 {
            return Err(ScanError::Socket(format!(
                "socket() fehlgeschlagen: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Interface-Index ermitteln (SIOCGIFINDEX) und Socket daran binden
        let mut ifr: libc::ifreq = mem::zeroed();
        let name_len = iface.len().min(ifr.ifr_name.len() - 1);
        std::ptr::copy_nonoverlapping(
            iface.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_len,
        );
        if libc::ioctl(sock, libc::SIOCGIFINDEX, &mut ifr as *mut _ as *mut c_void) < 0 {
            let _ = libc::close(sock);
            return Err(ScanError::Socket(format!(
                "ioctl(SIOCGIFINDEX) fehlgeschlagen: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut addr: sockaddr_ll = mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        addr.sll_ifindex = ifr.ifr_ifru.ifru_ifindex as i32;
        addr.sll_hatype = libc::ARPHRD_ETHER;
        addr.sll_pkttype = libc::PACKET_BROADCAST;
        if libc::bind(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<sockaddr_ll>() as u32,
        ) < 0
        {
            let _ = libc::close(sock);
            return Err(ScanError::Socket(format!(
                "bind() fehlgeschlagen: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(sock)
    }
}

/// Baue ein ARP-Who-Has-Paket für die angegebene Ziel-IP.
#[cfg(target_os = "linux")]
fn build_arp_request(
    sender_ip: &std::net::Ipv4Addr,
    sender_mac: &[u8; 6],
    target_ip: &std::net::Ipv4Addr,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(42);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // Hardware-Type (Ethernet)
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // Protokoll (IPv4)
    pkt.push(6); // Hardware-Größe
    pkt.push(4); // Protokoll-Größe
    pkt.extend_from_slice(&1u16.to_be_bytes()); // Operation (Request)
    pkt.extend_from_slice(sender_mac); // Sender-MAC
    pkt.extend_from_slice(&sender_ip.octets()); // Sender-IP
    pkt.extend_from_slice(&[0u8; 6]); // Ziel-MAC (Broadcast)
    pkt.extend_from_slice(&target_ip.octets()); // Ziel-IP
    pkt
}

/// Führe einen ARP-Sweep über den angegebenen IP-Bereich durch.
///
/// # Parameter
/// - `iface`: Netzwerkschnittstelle (z.B. "eth0")
/// - `range_start` / `range_end`: IP-Bereich
/// - `own_ip` / `own_mac`: eigene Identität für die ARP-Anfragen
///
/// # Rückgabe
/// Liste der entdeckten Hosts mit MAC- und IP-Adresse.
#[cfg(target_os = "linux")]
pub fn arp_sweep(
    iface: &str,
    range_start: &std::net::Ipv4Addr,
    range_end: &std::net::Ipv4Addr,
    own_ip: &std::net::Ipv4Addr,
    own_mac: &[u8; 6],
) -> Result<Vec<DiscoveredHost>, ScanError> {
    let sock = create_arp_socket(iface)?;
    let mut discovered: HashMap<[u8; 6], IpAddr> = HashMap::new();

    // ARP-Anfragen für den gesamten Bereich senden
    let mut current = u32::from(*range_start);
    let end = u32::from(*range_end);
    while current <= end {
        let target_ip = std::net::Ipv4Addr::from(current);
        let pkt = build_arp_request(own_ip, own_mac, &target_ip);
        unsafe {
            let mut addr: sockaddr_ll = mem::zeroed();
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
            addr.sll_ifindex = 0; // Broadcast
            addr.sll_hatype = libc::ARPHRD_ETHER;
            addr.sll_pkttype = libc::PACKET_BROADCAST;
            let _ = libc::sendto(
                sock,
                pkt.as_ptr() as *const c_void,
                pkt.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            );
        }
        current = current.wrapping_add(1);
    }

    // Socket auf 2 Sekunden Receive-Timeout setzen
    unsafe {
        let tv: libc::timeval = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let _ = libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const c_void,
            mem::size_of::<libc::timeval>() as u32,
        );
    }

    // Antworten sammeln bis Timeout
    let mut buf = [0u8; 512];
    loop {
        unsafe {
            let mut from: sockaddr_ll = mem::zeroed();
            let mut addrlen = mem::size_of::<sockaddr_ll>() as u32;
            let n = libc::recvfrom(
                sock,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut addrlen,
            );
            if n <= 0 {
                break; // Timeout oder Fehler
            }
            // ARP-Antwort parsen (Operation = 2, bei Offset 8-9)
            if n as usize >= 24 && buf[8] == 0 && buf[9] == 2 {
                let sender_mac: [u8; 6] = buf[14..20].try_into().unwrap();
                let sender_ip = IpAddr::V4(std::net::Ipv4Addr::from([
                    buf[20], buf[21], buf[22], buf[23],
                ]));
                if !discovered.contains_key(&sender_mac) {
                    debug!("ARP-Antwort von {}", sender_ip);
                    discovered.insert(sender_mac, sender_ip);
                }
            }
        }
    }
    unsafe {
        libc::close(sock);
    }
    Ok(discovered
        .into_iter()
        .map(|(mac, ip)| DiscoveredHost { mac, ip })
        .collect())
}

/// Nicht-Linux-Plattformen: der ARP-Sweep braucht AF_PACKET-Raw-Sockets und
/// existiert nur unter Linux. Der Aufrufer bekommt einen klaren Fehler statt
/// eines Build-Bruchs.
#[cfg(not(target_os = "linux"))]
pub fn arp_sweep(
    _iface: &str,
    _range_start: &std::net::Ipv4Addr,
    _range_end: &std::net::Ipv4Addr,
    _own_ip: &std::net::Ipv4Addr,
    _own_mac: &[u8; 6],
) -> Result<Vec<DiscoveredHost>, ScanError> {
    Err(ScanError::Unsupported(
        "ARP-Sweep benötigt AF_PACKET-Raw-Sockets und ist nur unter Linux verfügbar".into(),
    ))
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    /// Außerhalb von Linux liefert der Sweep einen klaren Fehler statt zu
    /// fehlschlagen. Der Fehler muss an der Aufrufstelle greifbar sein.
    #[test]
    fn arp_sweep_reports_unsupported_off_linux() {
        let err = arp_sweep(
            "eth0",
            &std::net::Ipv4Addr::new(192, 168, 1, 1),
            &std::net::Ipv4Addr::new(192, 168, 1, 254),
            &std::net::Ipv4Addr::new(192, 168, 1, 100),
            &[0u8; 6],
        )
        .expect_err("der Sweep ist außerhalb von Linux nicht verfügbar");
        assert!(matches!(err, ScanError::Unsupported(_)));
    }
}
