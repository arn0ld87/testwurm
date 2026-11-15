---
id: ISSUE-2
title: SMB-Relay ist toter Code — Port 445 fehlt in COMMON_PORTS
status: done
category: bug
triage_state: erledigt
agent_brief: briefs/ISSUE-2-smb-relay-betriebsfaehig.md
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

## Acceptance Criteria## Acceptance Criteria

- [ ] Das Relay-Skript liegt im Repository, und die Standard-Konfiguration verweist darauf
- [ ] Ein Test belegt, dass Port 445 im Scan-Ergebnis erscheint
- [ ] Fehlt das Skript oder Python, entsteht ein kontrollierter Fehler statt eines Hängers
- [ ] Die Herkunft und Lizenz des Skripts sind im Repository dokumentiert
- [ ] Jede Zuordnung im Port-zu-Dienst-Mapping ist erreichbar, oder das Mapping wird gekürzt

## Technical Notes

- Betroffen: `kx/crates/kx-scanner/src/tcp_scan.rs:27` (COMMON_PORTS), `kx/crates/kx-agent/src/propagate.rs:66,74,82`
- `COMMON_PORTS` wird auch vom Beispiel-Binary `kx-exploit/examples/demo_worm.rs` genutzt und dort mit dem gleichen 445-Problem
- Alternativ: `scan_tcp` mit einer expliziten Portliste für den Exploit-Pfad aufrufen (`scan_tcp(&ips, &[445, 22], 1000)`), statt die gemeinsame Konstante zu verändern — dann bleibt `COMMON_PORTS` als „typische Dienste" semantisch sauber
- Achtung bei Erweiterung von `COMMON_PORTS`: mehr Ports bedeuten mehr TCP-Verbindungen pro Host (aktuell 10 pro Host), was die Scanzeit linear verlängert

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der Port-Fix ist vorhanden: 445 steht in der gescannten Portliste, und das
  Port-zu-Dienst-Mapping kennt den SMB-Dienst. Der ursprüngliche Kernbefund
  dieser Issue ist damit behoben.
- Der Ausführungspfad ist es nicht: Das referenzierte Relay-Skript liegt nicht im
  Repository. Jeder Aufruf scheitert an der fehlenden Datei, bevor eine
  Verbindung zum Ziel zustande kommt. Diese Ursache war in der Issue nicht
  benannt.
- Es fehlt weiterhin der Test, der 445 im Scan-Ergebnis belegt.
- Das Mapping ist nicht vollständig konsistent: mehrere Zuordnungen (23, 25, 8443,
  2375/2376) haben keine Entsprechung in der gescannten Portmenge.

**Triage-Entscheidung:** Der Scope wird erweitert — das Skript wird als
Repository-Asset mitgeliefert, der Port-Fix bleibt, der fehlende Test wird
nachgezogen. Agent Brief: [`briefs/ISSUE-2-smb-relay-betriebsfaehig.md`](briefs/ISSUE-2-smb-relay-betriebsfaehig.md)
**Erledigt am 2026-11-15:** Das Relay-Skript liegt als Asset im Repository
(`kx/assets/smbrelayx.py`, Impacket 0.11.0, Apache-Lizenz, Herkunft und
Prüfsumme in `kx/assets/README.md`). Der Aufruf nutzt die reale CLI des Skripts
(`-h`, `-domain`, `-c`, `-one-shot`) statt der Flags, die es in keiner Version
gibt. Fehlt das Skript, endet der Versuch kontrolliert mit
`ExploitError::ImpacketMissing`; der Subprozess läuft unter einer Zeitgrenze von
120 s. Der Parser liest die drei Hash-Formen von Impacket und Mimikatz.
`service_for_port` und die Scanliste sind deckungsgleich, ein Test hält das
fest; 445 ist in der Scanliste, ein Test belegt das und einen offenen Port im
Scan-Ergebnis.

**Befund zum Issue-Text:** Die ursprüngliche Beschreibung nannte nur den
fehlenden Port. Der eigentliche Grund war breiter: das Skript fehlte im
Repository, die aufgerufenen Flags (`-d`, `--dump-command`) existieren in
keiner Impacket-Version, und der Hash-Parser las das falsche Feld. Ab Impacket
0.12 gibt es `smbrelayx.py` nicht mehr — das Asset ist deshalb die letzte
Version mit dem einmaligen Aufruf.
