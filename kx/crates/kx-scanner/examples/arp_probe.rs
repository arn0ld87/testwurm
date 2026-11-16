//! Probe fuer den ARP-Sweep: ruft `arp_sweep` direkt auf und druckt das
//! Ergebnis. Braucht Root (AF_PACKET-Raw-Socket).
//!
//! Aufruf:
//!   sudo ./arp_probe <iface> <start> <end> <eigene-ip> <eigene-mac>

use std::net::Ipv4Addr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "Aufruf: {} <iface> <start> <end> <eigene-ip> <eigene-mac>",
            args[0]
        );
        std::process::exit(2);
    }
    let iface = &args[1];
    let start: Ipv4Addr = args[2].parse().expect("Start-IP");
    let end: Ipv4Addr = args[3].parse().expect("End-IP");
    let own_ip: Ipv4Addr = args[4].parse().expect("eigene IP");
    let own_mac: Vec<u8> = args[5]
        .split(':')
        .map(|t| u8::from_str_radix(t, 16).expect("MAC-Byte"))
        .collect();
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&own_mac);

    println!("Sweep ueber {iface}: {start} bis {end}, eigene IP {own_ip}, MAC {own_mac:?}");
    match kx_scanner::arp_sweep(iface, &start, &end, &own_ip, &mac) {
        Ok(hosts) => {
            println!("Ergebnis: {} Host(s)", hosts.len());
            for h in hosts {
                println!(
                    "  {} {}",
                    h.ip,
                    h.mac.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
        }
        Err(e) => {
            println!("Fehler: {e}");
            std::process::exit(1);
        }
    }
}
