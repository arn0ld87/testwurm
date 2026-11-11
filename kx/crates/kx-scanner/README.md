# kx-scanner

## Overview
Manifest des Rust-Crates `kx-scanner` (`[Cargo.toml:package]`, Name `kx-scanner`, Lib-Target
`kx_scanner`, Pfad `src/lib.rs`, Beschreibung „Netzwerkerkennung und Service-Fingerprinting für
den Kx-Netzwerkwurm"). Das Crate ist eine Basislage des `kx`-Workspace: es deklariert **keine**
Abhängigkeit zu einem anderen Workspace-Crate und stützt sich ausschließlich auf externe Crates
— `serde`, `serde_json`, `thiserror`, `tracing`, `tokio` und `libc`
[Cargo.toml:dependencies]. `serde` und `serde_json` werden im Quellcode des Crates nirgends
verwendet; `thiserror` liefert den Fehlertyp, `tracing` die Debug-Logs, `tokio` die asynchrone
Netzwerklogik und `libc` die Raw-Socket-Aufrufe [Cargo.toml:dependencies].

Es ist Mitglied des Workspace `kx` (`members = ["crates/kx-scanner", ...]`, `resolver = "2"`,
Edition 2021, MSRV 1.77) und erbt `version`, `edition`, `rust-version`, `license` und `authors`
aus dem Workspace-Paketblock (`[Cargo.toml:package]` mit `version.workspace = true` usw.).

Das Crate liefert drei aktive Dienste: ARP-Sweep zur Layer-2-Hostentdeckung
[src/arp.rs:arp_sweep], asynchronen TCP-Connect-Portscan [src/tcp_scan.rs:scan_tcp] und
OS-/Dienst-Fingerprinting per Banner-Analyse [src/fingerprint.rs:fingerprint]. Es besitzt keine
eigene Zustandsverwaltung und keine Persistenz; alle externen Effekte stecken im Modulbaum
unter `src/`.

Plattformgrenze: Der ARP-Pfad nutzt `AF_PACKET`-Raw-Sockets und ist damit Linux-spezifisch; das
Crate enthält kein `cfg(target_os = ...)`-Gating und kompiliert auf macOS nicht
[src/arp.rs:arp_sweep]. Abhängige Crates sind `kx-agent` (ruft `kx_scanner::arp_sweep` und
`kx_scanner::scan_tcp` auf) und `kx-exploit` (verwendet `kx_scanner` in `examples/demo_worm.rs`);
beide ziehen den Compile-Abbruch auf macOS als Abhängigkeit mit.

## Subdirectories & Boundaries
- `src`: [./src/README.md](./src/README.md) - Vollständige Implementierung der öffentlichen
  Oberfläche: die Module `arp` (Layer-2-Hostentdeckung per Raw-Socket), `tcp_scan`
  (paralleler TCP-Connect-Scan), `fingerprint` (Banner-Analyse) und `error` (Fehlertyp) sowie
  die `pub use`-Re-Exports am Crate-Root. Alle externen Effekte (Raw-Socket-Versand,
  TCP-Verbindungen, Banner-Reads) stecken ausschließlich in diesem Modulbaum.

## Interface

Rollup aus [`src/`](./src/README.md):

- `pub fn arp_sweep(iface: &str, range_start: &Ipv4Addr, range_end: &Ipv4Addr, own_ip: &Ipv4Addr, own_mac: &[u8; 6]) -> Result<Vec<DiscoveredHost>, ScanError>` — Layer-2-Hostentdeckung per Raw-Socket; **synchron**, kein `async` [src/arp.rs:arp_sweep].
- `pub async fn scan_tcp(hosts: &[IpAddr], ports: &[u16], timeout_ms: u64) -> ScanResults` — asynchroner TCP-Connect-Portscan [src/tcp_scan.rs:scan_tcp].
- `pub async fn scan_common_ports(hosts: &[IpAddr], timeout_ms: u64) -> ScanResults` — delegiert an `scan_tcp(hosts, COMMON_PORTS, timeout_ms)` [src/tcp_scan.rs:scan_common_ports].
- `pub async fn fingerprint(host: IpAddr, port: u16, timeout_ms: u64) -> Option<ServiceInfo>` — OS-/Dienst-Erkennung per Banner-Analyse [src/fingerprint.rs:fingerprint].
- `pub fn identify_service(port: u16) -> &'static str` — öffentlich, aber **nicht** am Crate-Root re-exportiert; nur über `kx_scanner::fingerprint::identify_service` erreichbar [src/fingerprint.rs:identify_service].
- `pub struct DiscoveredHost` mit `mac` und `ip`; `pub struct ScanResults` mit `open_ports`; `pub struct ServiceInfo` mit `host`, `port`, `service`, `version`, `os`, `banner` [src/arp.rs:DiscoveredHost] [src/tcp_scan.rs:ScanResults] [src/fingerprint.rs:ServiceInfo].
- `pub enum ScanError` als Fehlertyp des Crates mit den Varianten `Socket(String)`, `Arp(String)`, `Tcp(String)`, `Timeout(String)` [src/error.rs:ScanError].
- `pub const COMMON_PORTS` — die feste Portliste `[22, 80, 135, 443, 1433, 1521, 3306, 5432, 5900, 8080]`, die Agent und Beispiel-Binary verwenden [src/tcp_scan.rs:COMMON_PORTS].

## Invariants

Rollup aus [`src/`](./src/README.md):

- Der Crate deklariert **keine** Abhängigkeit zu einem anderen Workspace-Crate; er ist eine Basislage [Cargo.toml:dependencies].
- `serde` und `serde_json` sind im Manifest deklariert, werden im Quellcode aber nirgends verwendet [Cargo.toml:dependencies].
- Das Crate enthält **kein** `#[cfg(target_os = ...)]`-Gating. Der ARP-Pfad nutzt `AF_PACKET`-Raw-Sockets und ist damit Linux-spezifisch; auf macOS kompiliert das Crate nicht [src/arp.rs:arp_sweep].
- `arp_sweep` benötigt `CAP_NET_RAW` oder Root-Rechte (Modul-Dokumentation) [src/arp.rs:arp_sweep].
- `scan_tcp` nimmt eine beliebige Portliste entgegen — nur `scan_common_ports` verwendet fest `COMMON_PORTS`; Agent und Beispiel-Binary rufen `scan_tcp` mit `COMMON_PORTS` und fest 1000 ms Timeout auf [src/tcp_scan.rs:scan_tcp] [src/tcp_scan.rs:scan_common_ports].
- `fingerprint` liest in einen festen 1024-Byte-Puffer; der Timeout ist ein Aufrufparameter, die Caller wählen ihn (das Beispiel-Binary 2000 ms) [src/fingerprint.rs:grab_banner].
- Das Crate bringt keine eigenen Tests mit — es existiert kein `#[cfg(test)]`-Modul [src/lib.rs:lib].

## Side Effects

Rollup aus [`src/`](./src/README.md):

- Netzwerk (Layer 2): `arp_sweep` öffnet einen Raw-Socket und sendet für jede IP des Bereichs eine ARP-Who-has-Broadcast-Anfrage [src/arp.rs:arp_sweep].
- Netzwerk (Layer 4): `scan_tcp` führt parallele TCP-Verbindungen zu jedem übergebenen Host aus, eine Task pro Host × Port [src/tcp_scan.rs:scan_tcp].
- Netzwerk (Banner): `fingerprint` verbindet sich zu jedem offenen Port und liest den Banner [src/fingerprint.rs:fingerprint].
- Logging über `tracing::debug!` für erkannte Hosts und Dienste [src/arp.rs:arp_sweep] [src/fingerprint.rs:fingerprint].

## Verification
- Run: `cargo test` (ausgeführt in der Workspace-Wurzel `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: Das Crate bringt keine eigenen Tests mit (`cargo test -p kx-scanner` meldet 0 Tests,
  kein `#[cfg(test)]`-Modul vorhanden). `arp.rs` ist vollständig mit
  `#[cfg(target_os = "linux")]` ausgezeichnet — der ARP-Sweep existiert damit nur unter
  Linux, das Crate selbst kompiliert und testet plattformübergreifend. `cargo test --workspace`
  endet auf macOS mit Exit-Code 0 (Stand 2026-11-11: 59 Tests grün, 0 Fehler).
