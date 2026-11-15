# kx-scanner/src

## Overview
Quellmodule des Crates `kx-scanner`. Die vier Module `arp`, `error`, `fingerprint` und
`tcp_scan` bilden die gesamte öffentliche Oberfläche; `lib.rs` deklariert sie per `pub mod` und
re-exportiert die wesentlichen Typen und Funktionen per `pub use` am Crate-Root
[lib.rs:pub mod arp].

Das Crate ist eine Basislage: es deklariert keine Abhängigkeit zu einem anderen Workspace-Crate,
sondern nur `serde`, `serde_json`, `thiserror`, `tracing`, `tokio` und `libc`
[../Cargo.toml:dependencies]. `serde` und `serde_json` werden im Quellcode des Crates nirgends
verwendet — es findet keine (De)Serialisierung statt [../Cargo.toml:dependencies].

Die drei aktiven Pfade sind: Layer-2-Hostentdeckung per ARP-Broadcast
[arp.rs:arp_sweep], asynchroner TCP-Connect-Portscan [tcp_scan.rs:scan_tcp] und
OS-/Dienst-Fingerprinting per Banner-Analyse [fingerprint.rs:fingerprint].

Plattformgrenze: `arp.rs` nutzt `std::os::unix::io::RawFd` und `AF_PACKET`-Raw-Sockets
[arp.rs:create_arp_socket]. Das Modul ist inzwischen vollständig mit
`#[cfg(target_os = "linux")]` ausgezeichnet, das Crate kompiliert daher auf allen
Plattformen — **nur** der ARP-Sweep existiert exklusiv unter Linux
[arp.rs:arp_sweep].

## Interface
- `pub mod arp`, `pub mod error`, `pub mod fingerprint`, `pub mod tcp_scan` — die vier
  öffentlichen Module des Crates [lib.rs:pub mod arp]
- Re-Exports am Crate-Root: `arp_sweep`, `DiscoveredHost`, `ScanError`, `fingerprint`,
  `ServiceInfo`, `scan_common_ports`, `scan_tcp`, `ScanResults`, `COMMON_PORTS` [lib.rs:pub use]
- `pub enum ScanError` — `#[derive(Debug, thiserror::Error)]`, vier Varianten mit je einem
  `String`-Payload: `Socket(String)`, `Arp(String)`, `Tcp(String)`, `Timeout(String)`, jede mit
  eigenem `#[error]`-Display-Text [error.rs:ScanError]
- `pub struct DiscoveredHost { pub mac: [u8; 6], pub ip: IpAddr }` —
  `#[derive(Debug, Clone, PartialEq, Eq)]` [arp.rs:DiscoveredHost]
- `pub fn arp_sweep(iface: &str, range_start: &Ipv4Addr, range_end: &Ipv4Addr, own_ip: &Ipv4Addr,
  own_mac: &[u8; 6]) -> Result<Vec<DiscoveredHost>, ScanError>` [arp.rs:arp_sweep]
- Private Helfer, nicht am Crate-Root exportiert: `create_arp_socket`, `build_arp_request`
  [arp.rs:create_arp_socket]
- `pub struct ScanResults { pub open_ports: HashMap<IpAddr, Vec<u16>> }` —
  `#[derive(Debug, Clone)]` [tcp_scan.rs:ScanResults]
- `impl ScanResults { pub fn new() -> Self }` — erzeugt eine leere Ergebnis-Map [tcp_scan.rs:ScanResults::new]
- `pub const COMMON_PORTS: &[u16]` — `[22, 80, 135, 443, 1433, 1521, 3306, 3389, 445, 5432, 5900, 8080]`
  [tcp_scan.rs:COMMON_PORTS]
- `pub async fn scan_tcp(hosts: &[IpAddr], ports: &[u16], timeout_ms: u64) -> ScanResults`
  [tcp_scan.rs:scan_tcp]
- `pub async fn scan_common_ports(hosts: &[IpAddr], timeout_ms: u64) -> ScanResults` —
  delegiert an `scan_tcp(hosts, COMMON_PORTS, timeout_ms)` [tcp_scan.rs:scan_common_ports]
- `pub struct ServiceInfo { pub host: IpAddr, pub port: u16, pub service: String,
  pub version: Option<String>, pub os: Option<String>, pub banner: String }` —
  `#[derive(Debug, Clone)]` [fingerprint.rs:ServiceInfo]
- `impl ServiceInfo { pub fn new(host: IpAddr, port: u16, service: String) -> Self }` — setzt
  `version: None`, `os: None`, `banner: String::new()` [fingerprint.rs:ServiceInfo::new]
- `pub fn identify_service(port: u16) -> &'static str` — öffentlich, aber **nicht** am Crate-Root
  re-exportiert; nur über `kx_scanner::fingerprint::identify_service` erreichbar
  [fingerprint.rs:identify_service]
- `pub async fn fingerprint(host: IpAddr, port: u16, timeout_ms: u64) -> Option<ServiceInfo>`
  [fingerprint.rs:fingerprint]
- Privater Helfer, nicht exportiert: `grab_banner` [fingerprint.rs:grab_banner]

## Invariants
- `ScanError` ist der einzige Fehlertyp des Crates, und nur die Variante `Socket` wird
  tatsächlich konstruiert — `Arp`, `Tcp` und `Timeout` existieren, werden aber nirgends
  erzeugt [arp.rs:create_arp_socket]
- FD-Hygiene: der Raw-Socket wird im Fehlerpfad von `ioctl(SIOCGIFINDEX)` und von `bind()`
  sowie am Ende von `arp_sweep` mit `libc::close(sock)` geschlossen [arp.rs:create_arp_socket]
- Byte-Order: das Protokollfeld wird als `ETH_P_ARP.to_be()` in `socket()` und in
  `sockaddr_ll.sll_protocol` geschrieben (Netz-Byte-Order) [arp.rs:create_arp_socket]
- Der Interface-Name wird auf `ifr.ifr_name.len() - 1` Zeichen gekürzt und per
  `copy_nonoverlapping` **ohne** Null-Terminator in das nullinitialisierte `libc::ifreq`
  kopiert; ein zu langer Name wird still abgeschnitten [arp.rs:create_arp_socket]
- Der Adressbereich ist inklusiv (`while current <= end`) und läuft über
  `current.wrapping_add(1)`; ein überlaufender Bereich läuft auf 0 weiter statt zu panicen
  [arp.rs:arp_sweep]
- `build_arp_request` erzeugt exakt 28 Byte ARP-Payload in fester Reihenfolge — Hardware-Type 1
  (Ethernet), Protokoll 0x0800 (IPv4), hlen 6, plen 4, Operation 1 (Request), 6 Byte Sender-MAC,
  4 Byte Sender-IP, 6 Null-Byte als Ziel-MAC (Broadcast), 4 Byte Ziel-IP. Der Puffer wird mit
  `Vec::with_capacity(42)` reserviert, geschrieben werden aber nur 28 Byte — ein 14 Byte großer
  Ethernet-Header wird nicht abgelegt [arp.rs:build_arp_request]
- Der Empfangs-Timeout wird über `setsockopt(SO_RCVTIMEO)` exakt auf
  `timeval { tv_sec: 2, tv_usec: 0 }` gesetzt und gilt für alle folgenden `recvfrom`-Aufrufe
  [arp.rs:arp_sweep]
- Die Empfangsschleife bricht ab, sobald `recvfrom` `n <= 0` liefert (Timeout oder Fehler)
  [arp.rs:arp_sweep]
- Die Antwortfilter-Bedingung lautet `n >= 24 && buf[8] == 0 && buf[9] == 2`; der Opcode-Check
  ist Bestandteil der Bedingung, nicht der Längenprüfung [arp.rs:arp_sweep]
- Offset-Abweichung der Antwortauswertung: die Absenderfelder werden bei `buf[14..20]`
  (MAC) und `buf[20..24]` (IP) gelesen und der Opcode bei `buf[8]`/`buf[9]`. Im reinen
  ARP-Payload liegen Opcode, Absender-MAC und Absender-IP dagegen bei 6-7, 8-13 und 14-17, im
  vollständigen Ethernet-Frame (14-Byte-Header) bei 20-21, 22-27 und 28-31 — die Bedingung
  `buf[8] == 0 && buf[9] == 2` trifft unter keinem dieser Layouts zuverlässig zu
  [arp.rs:arp_sweep]
- Die Längenprüfung `n >= 24` sichert den Indexzugriff auf `buf[20..24]` ab; das
  `try_into().unwrap()` auf `buf[14..20]` ist für sich genommen panic-frei, weil dieser Slice
  unabhängig von `n` immer genau 6 Elemente lang ist [arp.rs:arp_sweep]
- Deduplizierung: pro MAC-Adresse wird höchstens ein Host eingetragen; der Schlüssel ist die
  MAC-Adresse, nicht die IP [arp.rs:arp_sweep]
- Die Rückgabeliste von `arp_sweep` entsteht aus `HashMap::into_iter()` und hat daher keine
  deterministische Reihenfolge [arp.rs:arp_sweep]
- Ein Port gilt nur dann als offen, wenn `TcpStream::connect` innerhalb von `conn_timeout`
  erfolgreich war; Connect-Fehler und Timeout werden beide zu `false` [tcp_scan.rs:scan_tcp]
- `conn_timeout = Duration::from_millis(timeout_ms)` gilt pro Verbindungsversuch (Host × Port),
  nicht pro Scan [tcp_scan.rs:scan_tcp]
- `scan_tcp` hat keinen Fehler-Rückgabepfad: Join-Fehler der gespawnten Tasks werden über
  `if let Ok(...)` verworfen, das Ergebnis ist immer ein `ScanResults` [tcp_scan.rs:scan_tcp]
- `results.open_ports.entry(host).or_default().push(port)` legt einen Host-Key nur an, wenn
  mindestens ein offener Port gefunden wurde — Hosts ohne offene Ports fehlen vollständig in der
  Map [tcp_scan.rs:scan_tcp]
- Die Handles werden in Nested-Loop-Reihenfolge (Host außen, Port innen) erzeugt und in dieser
  Reihenfolge awaited; die `Vec<u16>` je Host folgt damit der Reihenfolge des `ports`-Slices,
  doppelte Einträge im Slice erzeugen doppelte Ports im Ergebnis [tcp_scan.rs:scan_tcp]
- Für jedes Paar (Host, Port) wird genau eine Tokio-Task gespawnt, jede mit eigenem
  `TcpStream::connect` [tcp_scan.rs:scan_tcp]
- `grab_banner` liefert `Err(())` bei Connect-Timeout, Connect-Fehler, Lesefehler oder `n == 0` —
  ein leeres Banner gilt als Fehlschlag [fingerprint.rs:grab_banner]
- Derselbe `timeout_ms` wird sowohl für `TcpStream::connect` als auch für `stream.read`
  verwendet; der Lesepuffer ist fest `[0u8; 1024]`, das Banner wird per
  `String::from_utf8_lossy` dekodiert (ungültige UTF-8-Sequenzen werden ersetzt, nicht als
  Fehler behandelt) [fingerprint.rs:grab_banner]
- `fingerprint` gibt `None` ausschließlich bei fehlgeschlagenem Banner-Griff zurück; bei
  erfolgreichem Banner ist das Ergebnis immer `Some(ServiceInfo)` [fingerprint.rs:fingerprint]
- Die Port-zu-Dienst-Zuordnung in `identify_service` ist eine geschlossene Tabelle
  (22/80/135/443/1433/1521/3306/5432/5900/8080); jeder andere Port ergibt `"unknown"`
  [fingerprint.rs:identify_service]
- Die OS-Erkennung ist eine `if`/`else if`-Kette, kein Matching mit Mehrfachzuordnung — ein
  Banner mit `SSH-` und `Microsoft` wird als SSH behandelt und `os` bleibt `None`
  [fingerprint.rs:fingerprint]
- `version` wird ausschließlich im SSH-Zweig gesetzt und ist das erste
  whitespace-getrennte Token des Banners; bei Nicht-SSH-Bannern bleibt `version == None`
  [fingerprint.rs:fingerprint]
- `os` wird nur gesetzt, wenn das Banner `OpenSSH` (→ `"Linux/Unix"`), `Microsoft` oder
  `Windows` (→ `"Windows"`) enthält; sonst bleibt `os == None` [fingerprint.rs:fingerprint]
- `info.banner` wird vor der Pattern-Auswertung mit dem Rohbanner gefüllt und bleibt unverändert
  [fingerprint.rs:fingerprint]
- Die Portmenge von `COMMON_PORTS` umfasst zwölf Ports, darunter SMB (445) und RDP (3389) —
  ohne 445 wäre der SMB-Relay-Zweig des Agenten toter Code [tcp_scan.rs:COMMON_PORTS]
- `arp.rs` ist Linux-spezifisch (`AF_PACKET`, `std::os::unix::io::RawFd`) und setzt
  `CAP_NET_RAW` bzw. Root-Rechte voraus; das Modul ist vollständig mit
  `#[cfg(target_os = "linux")]` ausgezeichnet, sodass das Crate auf macOS und Windows
  ohne diese Funktionen kompiliert [arp.rs:create_arp_socket]

## Side Effects
- Netzwerk — Raw-Socket-Erzeugung: `libc::socket(AF_PACKET, SOCK_RAW, ETH_P_ARP.to_be())` erzeugt
  einen Raw-Socket auf Layer 2 [arp.rs:create_arp_socket]
- Netzwerk — Interface-Auflösung: `libc::ioctl(sock, SIOCGIFINDEX, ...)` ermittelt den
  Interface-Index des übergebenen `iface` [arp.rs:create_arp_socket]
- Netzwerk — Socket-Bindung: `libc::bind(sock, &sockaddr_ll)` bindet den Raw-Socket an
  AF_PACKET/ARP mit `sll_ifindex`, `sll_hatype = ARPHRD_ETHER`, `sll_pkttype = PACKET_BROADCAST`
  [arp.rs:create_arp_socket]
- Netzwerk — ARP-Broadcast-Versand: `libc::sendto(...)` versendet pro IP des Bereichs ein
  ARP-Who-Has-Broadcast-Paket (28 Byte) an alle Interfaces (`sll_ifindex = 0`); der
  Rückgabewert von `sendto` wird verworfen [arp.rs:arp_sweep]
- Netzwerk — Socket-Option: `libc::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, 2s)` verändert den
  Empfangs-Timeout des Sockets [arp.rs:arp_sweep]
- Netzwerk — Empfang: `libc::recvfrom(sock, buf, 512, ...)` liest ARP-Antworten direkt vom
  Raw-Socket in einen 512-Byte-Puffer [arp.rs:arp_sweep]
- Ressourcen — File-Deskriptor: `libc::close(sock)` in den Fehlerpfaden von `ioctl` und `bind`
  sowie am Ende von `arp_sweep` [arp.rs:create_arp_socket]
- Speicher (unsafe) — `std::ptr::copy_nonoverlapping(...)` schreibt den Interface-Name in das
  nullinitialisierte `libc::ifreq` [arp.rs:create_arp_socket]
- Speicher — `discovered.insert(sender_mac, sender_ip)` füllt die lokale
  `HashMap<[u8; 6], IpAddr>` während des Sweeps [arp.rs:arp_sweep]
- Netzwerk — ausgehende TCP-Verbindungen: `tokio::time::timeout(conn_timeout,
  TcpStream::connect(addr))` baut pro Host × Port eine TCP-Verbindung auf (Connect-Methode, kein
  SYN-Sweep) [tcp_scan.rs:scan_tcp]
- Nebenläufigkeit — `tokio::spawn(...)` erzeugt eine Tokio-Task pro Host × Port; die Handles
  werden anschließend awaited [tcp_scan.rs:scan_tcp]
- Speicher — `results.open_ports.entry(host).or_default().push(port)` fügt offene Ports in die
  Ergebnis-Map ein [tcp_scan.rs:scan_tcp]
- Netzwerk — Dienst-Banner: `TcpStream::connect(addr)` und anschließend `stream.read(&mut buf)` in
  einen 1024-Byte-Puffer lesen das Banner des Zieldienstes [fingerprint.rs:grab_banner]
- Speicher — `info.banner = banner.clone()`, `info.version = ...` und `info.os = Some(...)`
  verändern das zurückgegebene `ServiceInfo` [fingerprint.rs:fingerprint]
- Logging — `tracing::debug!("Offener Port: {}:{}")` je offenem Port [tcp_scan.rs:scan_tcp]
- Logging — `tracing::debug!("ARP-Antwort von {}")` je neuer MAC [arp.rs:arp_sweep]
- Logging — `tracing::debug!("Fingerprint für {}:{}")` je erfolgreichem Fingerprint
  [fingerprint.rs:fingerprint]
- Keine Dateisystem-, Prozess-, Lock- oder Environment-Zugriffe: in keiner der fünf Quelldateien
  kommen `fs`/`File`/`Command`/`Mutex`/`RwLock`/`std::env`/`process::` vor; der einzige
  Lesezugriff ist der TCP-Banner-Read, der einzige Spawn ist `tokio::spawn` [lib.rs:pub mod arp]

## Verification
- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: Das Crate bringt keine eigenen Tests mit — in `src/` existiert kein `#[cfg(test)]`-
  Modul und keine `#[test]`-Funktion [lib.rs:pub mod arp].
- Der Testlauf ist plattformübergreifend ausführbar: `arp.rs` ist vollständig mit
  `#[cfg(target_os = "linux")]` ausgezeichnet, die Linux-only-Symbole (`libc::sockaddr_ll`,
  `AF_PACKET`, `ETH_P_ARP`, `SIOCGIFINDEX`, `ARPHRD_ETHER`, `PACKET_BROADCAST` und das Feld
  `ifr.ifr_ifru.ifru_ifindex`) werden auf Nicht-Linux-Zielen nicht übersetzt.
  `cargo test --workspace` endet auf macOS mit Exit-Code 0.
- Stand (2026-11-11): `cargo test --workspace` → **59 Tests grün, 0 Fehler**. Davon entfallen
  3 auf `kx-scanner` selbst — das Crate bringt keine eigenen Tests mit, die 3 stammen aus den
  abhängigen Crates.
