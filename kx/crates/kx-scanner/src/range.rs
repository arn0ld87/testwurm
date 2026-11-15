//! Der Adressbereich, den der Agent abklopft, wenn kein ARP da ist.
//!
//! Der ARP-Sweep braucht AF_PACKET-Raw-Sockets und gibt es nur unter Linux.
//! Auf Windows und auf macOS ohne `CAP_NET_RAW` muss der Bereich anders
//! gefunden werden: nicht durch eine Frage an das Netz, sondern indem jede
//! Adresse als Kandidat gilt und der TCP-Scan entscheidet, wer antwortet.

use std::net::Ipv4Addr;

/// Die Höchstzahl der Adressen, die ein Bereich umfassen darf.
///
/// Ein Bereich von /16 wäre 65 536 Kandidaten — der TCP-Scan darüber läuft
/// ewig. Der Grenzwert macht das Fehlverhalten sichtbar, statt es zu
/// verstecken.
pub const MAX_BEREICH: u32 = 4096;

/// Die Adressen zwischen `start` und `end`, beide einschliesslich.
///
/// Ist `end` kleiner als `start`, kommt die leere Liste zurueck. Uebersteigt
/// der Bereich [`MAX_BEREICH`], wird er abgeschnitten — der Rest fehlt dann
/// allerdings, das gehoert in die Meldung des Aufrufers.
pub fn ip_range(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Addr> {
    let von = u32::from(start);
    let bis = u32::from(end);
    if bis < von {
        return Vec::new();
    }
    (von..=bis.min(von + MAX_BEREICH - 1))
        .map(Ipv4Addr::from)
        .collect()
}

/// Passt der Bereich in die Grenze, oder muss der Aufrufer warnen?
pub fn bereich_ist_zu_gross(start: Ipv4Addr, end: Ipv4Addr) -> bool {
    u32::from(end).saturating_sub(u32::from(start)) >= MAX_BEREICH
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn der_bereich_ist_vollstaendig() {
        let bereich = ip_range(ip("10.0.0.1"), ip("10.0.0.4"));
        assert_eq!(bereich.len(), 4);
        assert_eq!(bereich[0], ip("10.0.0.1"));
        assert_eq!(bereich[3], ip("10.0.0.4"));
    }

    #[test]
    fn ein_einzelner_host_ist_ein_bereich_von_einer_adresse() {
        let bereich = ip_range(ip("10.0.0.7"), ip("10.0.0.7"));
        assert_eq!(bereich, vec![ip("10.0.0.7")]);
    }

    #[test]
    fn ein_verkehrter_bereich_ist_leer() {
        assert!(ip_range(ip("10.0.0.9"), ip("10.0.0.1")).is_empty());
    }

    #[test]
    fn ein_zu_grosser_bereich_wird_abgeschnitten() {
        let bereich = ip_range(ip("10.0.0.0"), ip("10.255.255.255"));
        assert_eq!(bereich.len(), MAX_BEREICH as usize);
        assert!(bereich_ist_zu_gross(ip("10.0.0.0"), ip("10.255.255.255")));
    }

    #[test]
    fn ein_passender_bereich_wird_nicht_geschnitten() {
        assert!(!bereich_ist_zu_gross(ip("10.0.0.0"), ip("10.0.15.255")));
    }
}
