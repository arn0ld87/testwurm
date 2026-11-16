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
fn create_arp_socket(iface: &str) -> Result<(RawFd, i32), ScanError> {
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
        // Beim Binden keinen Protokollfilter setzen: der Kernel wertet
        // sll_protocol hier als Host-Order-Wert aus und vergleicht ihn mit
        // dem Protokoll des empfangenen Pakets. Mit htons(ETH_P_ARP) passt
        // dieser Vergleich nie, und der Socket verwirft jede Antwort.
        // Mit 0 nimmt der Socket alle Protokolle an - der Socket selbst
        // (socket() mit htons(ETH_P_ARP)) filtert ohnehin auf ARP.
        addr.sll_protocol = 0;
        addr.sll_ifindex = ifr.ifr_ifru.ifru_ifindex as i32;
        addr.sll_hatype = libc::ARPHRD_ETHER;
        // sll_pkttype bleibt 0: der Kernel uebernimmt den Wert als
        // Empfangsfilter. Steht dort PACKET_BROADCAST, nimmt der Socket
        // nur Broadcasts an - eine ARP-Antwort ist aber ein Unicast an
        // die eigene MAC und wird verworfen.
        addr.sll_pkttype = 0;
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
        Ok((sock, ifr.ifr_ifru.ifru_ifindex as i32))
    }
}

/// Länge des Ethernet-Headers, der jedem ARP-Frame voransteht.
#[cfg(target_os = "linux")]
const ETH_HEADER_LEN: usize = 14;

/// Liest die MAC-Adresse des Interfaces.
///
/// Ohne die echte MAC ist der ARP-Sweep sinnlos: die Gegenstelle beantwortet
/// eine Anfrage nicht, die von `00:00:00:00:00:00` kommt - sie kennt die
/// Absender-IP bereits und erwartet die Antwort auf der dazu gemeldeten MAC.
#[cfg(target_os = "linux")]
pub fn read_mac(iface: &str) -> Option<[u8; 6]> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return None;
        }
        let mut ifr: libc::ifreq = mem::zeroed();
        let name_len = iface.len().min(ifr.ifr_name.len() - 1);
        std::ptr::copy_nonoverlapping(
            iface.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_len,
        );
        if libc::ioctl(sock, libc::SIOCGIFHWADDR, &mut ifr as *mut _ as *mut c_void) < 0 {
            let _ = libc::close(sock);
            return None;
        }
        let _ = libc::close(sock);
        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = ifr.ifr_ifru.ifru_hwaddr.sa_data[i] as u8;
        }
        Some(mac)
    }
}

/// Außerhalb von Linux gibt es keine Raw-Sockets - dort liest der Aufrufer
/// die MAC nicht aus und klopft stattdessen den Bereich ab.
#[cfg(not(target_os = "linux"))]
pub fn read_mac(_iface: &str) -> Option<[u8; 6]> {
    None
}

/// Baue ein ARP-Who-Has-Paket für die angegebene Ziel-IP.
///
/// Der Ethernet-Header gehört dazu: Der Socket ist `SOCK_RAW` **mit**
/// Protokoll `ETH_P_ARP`. Nur bei `SOCK_RAW` ohne Protokollangabe baut der
/// Kernel den Ethernet-Header selbst — hier nicht. Ohne ihn geht ein um
/// 14 Bytes zu kurzes Frame auf die Leitung, die Gegenstelle verwirft es,
/// und der Sweep bleibt leer.
#[cfg(target_os = "linux")]
fn build_arp_request(
    sender_ip: &std::net::Ipv4Addr,
    sender_mac: &[u8; 6],
    target_ip: &std::net::Ipv4Addr,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(ETH_HEADER_LEN + 28);
    // Ethernet-Header (14 Bytes)
    pkt.extend_from_slice(&[0xff; 6]); // Ziel-MAC (Broadcast)
    pkt.extend_from_slice(sender_mac); // Quell-MAC
    pkt.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType (ARP)
                                                     // ARP-Header (28 Bytes)
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

/// Zerlegt einen empfangenen ARP-Frame in MAC und IP des Absenders.
///
/// Der Socket liefert den vollständigen Ethernet-Frame: 14 Bytes Header,
/// danach der ARP-Header. Die Felder liegen darum an diesen Offsets — wer
/// sie um 8 Bytes zu früh liest, verwirft jede Antwort und der Sweep
/// meldet eine leere Liste statt eines Fehlers.
///
/// Liefert `None` für alles, was keine ARP-Antwort ist.
#[cfg(target_os = "linux")]
fn parse_arp_reply(buf: &[u8]) -> Option<([u8; 6], std::net::IpAddr)> {
    if buf.len() < ETH_HEADER_LEN + 28 {
        return None;
    }
    if buf[12] != 0x08 || buf[13] != 0x06 {
        return None; // kein ARP
    }
    if buf[ETH_HEADER_LEN + 6] != 0 || buf[ETH_HEADER_LEN + 7] != 2 {
        return None; // ARP-Request, keine Antwort
    }
    let sender_mac: [u8; 6] = buf[ETH_HEADER_LEN + 8..ETH_HEADER_LEN + 14]
        .try_into()
        .ok()?;
    let sender_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from([
        buf[ETH_HEADER_LEN + 14],
        buf[ETH_HEADER_LEN + 15],
        buf[ETH_HEADER_LEN + 16],
        buf[ETH_HEADER_LEN + 17],
    ]));
    Some((sender_mac, sender_ip))
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
    let (sock, ifindex) = create_arp_socket(iface)?;
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
            addr.sll_ifindex = ifindex;
            addr.sll_hatype = libc::ARPHRD_ETHER;
            addr.sll_pkttype = libc::PACKET_BROADCAST;
            // Ohne Zieladresse nimmt der Kernel die Route zu sll_addr = 0
            // und der Request landet auf dem falschen Interface - oder gar
            // nicht. Der Fehler von sendto darf nicht wegfallen, sonst
            // bleibt der Sweep lautlos leer.
            addr.sll_addr[..4].copy_from_slice(&target_ip.octets());
            let gesendet = libc::sendto(
                sock,
                pkt.as_ptr() as *const c_void,
                pkt.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            );
            if gesendet < 0 {
                debug!(
                    "ARP-Request an {} liess sich nicht senden: {}",
                    target_ip,
                    std::io::Error::last_os_error()
                );
            }
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
            // ARP-Antwort parsen
            if let Some((sender_mac, sender_ip)) = parse_arp_reply(&buf[..n as usize]) {
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

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    const EIGENE_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x4b, 0x41, 0x4c];
    const ZIEL_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x4b, 0x41, 0x4d];

    /// Der Request muss den Ethernet-Header tragen: Der Socket ist SOCK_RAW
    /// **mit** Protokoll ETH_P_ARP, da baut der Kernel den Header nicht
    /// selbst. Ohne ihn geht ein um 14 Bytes zu kurzes Frame auf die
    /// Leitung, die Gegenstelle verwirft es, und der Sweep bleibt leer.
    #[test]
    fn build_arp_request_traegt_den_ethernet_header() {
        let pkt = build_arp_request(
            &std::net::Ipv4Addr::new(192, 168, 191, 142),
            &EIGENE_MAC,
            &std::net::Ipv4Addr::new(192, 168, 191, 143),
        );
        assert_eq!(pkt.len(), 42, "Ethernet-Header (14) plus ARP-Header (28)");
        assert_eq!(&pkt[0..6], &[0xff; 6], "Ziel-MAC ist Broadcast");
        assert_eq!(&pkt[6..12], &EIGENE_MAC, "Quell-MAC ist die eigene");
        assert_eq!(&pkt[12..14], &[0x08, 0x06], "EtherType ist ARP");
        assert_eq!(&pkt[20..22], &[0x00, 0x01], "Operation ist Request");
        assert_eq!(&pkt[22..28], &EIGENE_MAC, "Sender-MAC");
        assert_eq!(&pkt[28..32], &[192, 168, 191, 142], "Sender-IP");
        assert_eq!(&pkt[38..42], &[192, 168, 191, 143], "Ziel-IP");
    }

    /// Baut eine ARP-Antwort, wie der Socket sie liefert: Ethernet-Header
    /// vorn, danach der ARP-Header.
    fn arp_reply(mac: [u8; 6], ip: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&[0x08, 0x06]);
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&2u16.to_be_bytes()); // Operation: Reply
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[192, 168, 191, 142]);
        frame
    }

    /// Die Felder liegen hinter dem Ethernet-Header. Wer sie um 8 Bytes zu
    /// früh liest, verwirft jede Antwort - und der Sweep meldet eine leere
    /// Liste statt eines Fehlers.
    #[test]
    fn parse_arp_reply_liest_mac_und_ip_aus_dem_arp_header() {
        let frame = arp_reply(ZIEL_MAC, [192, 168, 191, 143]);
        let (mac, ip) = parse_arp_reply(&frame).expect("eine ARP-Antwort wird erkannt");
        assert_eq!(mac, ZIEL_MAC);
        assert_eq!(ip.to_string(), "192.168.191.143");
    }

    /// Eine Anfrage ist keine Antwort - sie darf nicht als Host gelten.
    #[test]
    fn parse_arp_reply_ignoriert_anfragen() {
        let mut frame = arp_reply(ZIEL_MAC, [192, 168, 191, 143]);
        frame[20] = 0;
        frame[21] = 1; // Operation: Request
        assert!(parse_arp_reply(&frame).is_none());
    }

    /// Ein Frame mit anderem EtherType ist kein ARP.
    #[test]
    fn parse_arp_reply_ignoriert_fremde_ethertypen() {
        let mut frame = arp_reply(ZIEL_MAC, [192, 168, 191, 143]);
        frame[13] = 0x00; // IPv4 statt ARP
        assert!(parse_arp_reply(&frame).is_none());
    }

    /// Zu kurze Frames werden verworfen, statt zu raten.
    #[test]
    fn parse_arp_reply_ignoriert_kurze_frames() {
        assert!(parse_arp_reply(&[0u8; 20]).is_none());
    }

    /// Die MAC muss vom Interface kommen: der Sweep nennt sie als Absender,
    /// und eine Gegenstelle beantwortet keine Anfrage von 00:00:00:00:00:00.
    #[test]
    fn read_mac_liest_vom_interface() {
        let mac = read_mac("lo").expect("das Loopback-Interface hat eine MAC");
        assert_eq!(
            mac, [0u8; 6],
            "das Loopback-Interface hat eine All-Zero-MAC"
        );
    }

    /// Ein Interface, das es nicht gibt, liefert keine MAC.
    #[test]
    fn read_mac_ist_none_fuer_unbekanntes_interface() {
        assert!(read_mac("kx-gibtesnicht").is_none());
    }
}
