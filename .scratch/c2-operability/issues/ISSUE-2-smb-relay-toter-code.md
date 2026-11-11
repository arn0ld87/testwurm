---
id: ISSUE-2
title: SMB-Relay ist toter Code — Port 445 fehlt in COMMON_PORTS
status: open
priority: high
---

## Description

Der dokumentierte und implementierte SMB-Relay→DCSync-Pfad des Agenten kann **nie** ausgeführt werden.

`run_propagation` in `kx-agent/src/propagate.rs:66` scannt ausschließlich die feste Portliste:

```rust
let scan: ScanResults = scan_tcp(&ips, kx_scanner::COMMON_PORTS, 1000).await;
```

`kx_scanner::COMMON_PORTS` (`kx-scanner/src/tcp_scan.rs:27-38`) lautet:

```
22, 80, 135, 443, 1433, 1521, 3306, 5432, 5900, 8080
```

**445 (SMB) ist nicht enthalten.** Der Zweig `if *port == 445` (`propagate.rs:74`) und damit der Aufruf `kx_exploit::smb_relay_dcsync` (`propagate.rs:82`) wird nie erreicht. `kx_exploit::smb_relay_dcsync` ist damit unerreichbarer Code im gesamten Workspace.

Dieselbe Ursache macht weitere Zuordnungen in `service_for_port` (`propagate.rs:26-45`) wirkungslos: 23 `telnet`, 25 `smtp`, 445 `smb`, 8443 `https-alt` und 2375/2376 `docker` können nie vorkommen.

Verifiziert am 2026-11-11 per Quellcode-Prüfung.

Related: ISSUE-3, ISSUE-6

## Acceptance Criteria

- [ ] Der Agent scannt SMB (445) — entweder durch Aufnahme von 445 in `COMMON_PORTS` oder durch einen eigenen Port-Satz für den Exploit-Pfad
- [ ] `smb_relay_dcsync` wird im Regelbetrieb erreichbar
- [ ] `service_for_port` und die gescannte Portmenge sind konsistent — jede Zuordnung im Mapping ist auch erreichbar, oder das Mapping wird entsprechend gekürzt
- [ ] Ein Test belegt, dass Port 445 im Scan-Ergebnis erscheint

## Technical Notes

- Betroffen: `kx/crates/kx-scanner/src/tcp_scan.rs:27` (COMMON_PORTS), `kx/crates/kx-agent/src/propagate.rs:66,74,82`
- `COMMON_PORTS` wird auch vom Beispiel-Binary `kx-exploit/examples/demo_worm.rs` genutzt und dort mit dem gleichen 445-Problem
- Alternativ: `scan_tcp` mit einer expliziten Portliste für den Exploit-Pfad aufrufen (`scan_tcp(&ips, &[445, 22], 1000)`), statt die gemeinsame Konstante zu verändern — dann bleibt `COMMON_PORTS` als „typische Dienste" semantisch sauber
- Achtung bei Erweiterung von `COMMON_PORTS`: mehr Ports bedeuten mehr TCP-Verbindungen pro Host (aktuell 10 pro Host), was die Scanzeit linear verlängert
