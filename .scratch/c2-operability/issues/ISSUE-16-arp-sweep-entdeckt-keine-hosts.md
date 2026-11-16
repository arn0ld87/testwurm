---
id: ISSUE-16
title: Der ARP-Sweep entdeckt keine Hosts — fünf Ursachen, die den Angriffspfad blockierten
status: done
priority: high
---

# Description

Der ARP-Sweep des Agenten hat nie einen Host gefunden. Beim ersten echten
Einsatz (Kali-VM gegen Windows-VM, 2026-11-16) meldete der Agent dauerhaft
„Keine Hosts entdeckt — Propagation beendet", obwohl `arp-scan` auf derselben
Maschine beide Ziele sofort sah.

Es sind fünf Fehler, die sich gegenseitig verdeckt haben. Jeder einzelne
hätte für sich den Sweep still scheitern lassen:

1. **`build_arp_request` ohne Ethernet-Header.** Der Socket ist `SOCK_RAW`
   **mit** Protokoll `ETH_P_ARP`. Nur bei `SOCK_RAW` *ohne* Protokollangabe
   baut der Kernel den Ethernet-Header selbst. Das Paket war 14 Bytes zu kurz
   und wurde von der Gegenstelle verworfen.
2. **Der Parser las die Felder um 8 Bytes zu früh.** Im Ethernet-Frame
   liegen der Opcode bei Offset 20–21, die Absender-MAC bei 22–27 und die IP
   bei 28–31. Der Code prüfte `buf[8]/buf[9]` als Opcode und las MAC ab 14
   und IP ab 20 — jede Antwort wurde verworfen.
3. **Der `bind` setzte `sll_protocol` auf `htons(ETH_P_ARP)`.** Der Kernel
   wertet das Feld als Host-Order-Wert aus und vergleicht es mit dem
   Protokoll des empfangenen Pakets — der Vergleich passt nie, der Socket
   verwirft alles. Mit `sll_protocol = 0` nimmt der Socket alle Protokolle
   an; der Socket selbst filtert ohnehin über `socket()`.
4. **Der `bind` setzte `sll_pkttype = PACKET_BROADCAST`.** Der Kernel
   übernimmt den Wert als Empfangsfilter. Damit nimmt der Socket nur
   Broadcasts an — eine ARP-Antwort ist aber ein Unicast an die eigene MAC
   und wird verworfen.
5. **Der Agent sendete mit der Absender-MAC `00:00:00:00:00:00`.**
   `main.rs` hatte dafür einen Platzhalter („in der Praxis vom System
   lesen"). Eine Gegenstelle beantwortet eine solche Anfrage nicht: sie
   kennt die Absender-IP bereits und erwartet die Antwort auf der MAC, die
   sie im Cache hat. Der Sweep lieferte darum `Ok([])` statt eines Fehlers —
   und der Fallback „Bereich abklopfen" griff nur, wenn `arp_sweep` ein
   `Err` lieferte. Genau deshalb blieb der Fehler lange unsichtbar.

# Acceptance Criteria

- [x] Der ARP-Request trägt den Ethernet-Header (Ziel-MAC Broadcast,
      Quell-MAC eigene, EtherType 0x0806).
- [x] Der Parser liest Opcode, MAC und IP an den richtigen Offsets.
- [x] Der `bind` setzt weder einen Protokoll- noch einen Pakettypfilter.
- [x] Der Agent liest die eigene MAC vom Interface (`SIOCGIFHWADDR`).
- [x] Der Fehler eines fehlgeschlagenen `sendto` wird nicht mehr
      verschluckt.
- [x] Tests decken den Ethernet-Header, die Parser-Offsets, die
      Unterscheidung Request/Reply und die MAC-Ermittlung ab.
- [x] Der Sweep findet im echten Betrieb die Windows-VM, der TCP-Scan
      erkennt 135/445/3389, und der Agent meldet den Host beim C2.

# Technical Notes

**Nachweis.** `kx-scanner/examples/arp_probe.rs` ruft `arp_sweep` direkt
auf und druckt das Ergebnis:

```bash
sudo ./arp_probe eth0 192.168.191.143 192.168.191.143 192.168.191.142 52:54:00:4b:41:4c
# Ergebnis: 1 Host(s)
#   192.168.191.143 5254004b414d
```

**Die Tests sind plattformgebunden.** Sie stehen unter
`#[cfg(all(test, target_os = "linux"))]` und laufen nur unter Linux. Der
Mac-Build überspringt sie — die CI-Matrix (ubuntu + macOS) prüft sie auf
ubuntu. Deshalb wurden sie zusätzlich auf rocky ausgeführt.

**Die Reihenfolge der Fehler war lehrreich.** Der Parser ließ sich mit der
echten Antwort aus der Leitung prüfen (der Ethernet-Header ist 14 Bytes,
der ARP-Header 28 — die Felder liegen bei 20/22/28). Der `bind` ließ sich
nur empirisch klären: ein Vergleich der Socket- und Bind-Varianten in
Python zeigte, dass nur `socket=htons(ARP)` mit `bind=0` antwortete.

**Nebenbefund, eigener Fix.** Das Relay-Skript schreibt seinen Fehler nach
stdout, nicht nach stderr. Der Rust-Code las nur stderr und meldete
darum „SMB-Relay fehlgeschlagen: " ohne Text — dieselbe Lehre wie bei
`sc.exe` und `schtasks` unter Windows. Der Aufruf liest jetzt beides.

**Offen (nicht Teil dieses Issues).** Der SMB-Relay beendet sich nach
„Running in relay mode" mit Code 1. Ein erfolgreicher Relay-DCSync
braucht ein AD-Umfeld mit Domain-Controller und Credentials; in dieser
Umgebung gibt es keinen DC. Dass der Wurm den Host erkennt, scannt und
den Exploit versucht, ist belegt.

**Related:** ISSUE-2 (SMB-Relay), ISSUE-3 (Credential-Test)
