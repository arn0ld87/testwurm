---
id: ISSUE-19
title: Der SMB-Relay bricht vor dem Start des Listeners ab
status: in-progress
priority: high
---

# ISSUE-19 — Der SMB-Relay bricht vor dem Start des Listeners ab

## Description

Im Betrieb auf `rocky` (2026-11-16, gegen die Windows-VM 192.168.191.143)
endete jeder SMB-Relay-Versuch mit Exit-Code 1 und **ohne Fehlermeldung**.
Die Meldung des Agenten lautete leer.

Zwei Ursachen, die sich gegenseitig verdeckt haben:

1. **Der Argument-Bug.** `smb_relay.rs` übergab `-domain` unbedingt (mit dem
   Default `WORKGROUP`), setzte aber nie `-machine-account` oder
   `-machine-hashes`. `smbrelayx.py` (Zeile 1203-1206) verlangt alle drei
   Argumente zusammen oder gar nicht und bricht in der halben Konfiguration
   mit `sys.exit(1)` ab — und zwar **bevor** `s.start()` den Listener öffnet.
   Der Exploit-Zweig ist seit der ersten Verdrahtung nie gelaufen.
2. **Der Diagnosekanal.** Impacket schreibt seine Meldungen nach `smb.log` im
   Arbeitsverzeichnis, nicht nach stderr. Der Code las nur stderr und meldete
   deshalb einen Fehler ohne Text.

Die verbreitete Erklärung, ein Relay-DCSync brauche zwingend ein
Active-Domain, ist damit widerlegt: der Versuch kam nie bis zum Netzwerk.

## Acceptance Criteria

- `-domain` wird nur übergeben, wenn `-machine-account` und
  `-machine-hashes` ebenfalls gesetzt sind. Ist nur `-domain` gesetzt, bricht
  der Versuch mit einer klaren Fehlermeldung ab, statt das Skript in einen
  `exit(1)` laufen zu lassen.
- Schlägt der Versuch fehl, steht der Inhalt von `smb.log` in der
  Fehlermeldung — der eigentliche Grund ist damit sichtbar.
- Unit-Tests decken die drei Fälle ab: Domain allein, alle drei zusammen,
  gar kein Domain.
- Der Tracker wird nachgeführt: ISSUE-2 wird wiedereröffnet (der Relay ist
  nicht erfolgreich nachgewiesen), ISSUE-3 ebenfalls (der
  Credential-Test ist SSH-only und war gegen ein Windows-Ziel nie aktiv).

## Technical Notes

- `RelayConfig` bekommt die Felder `machine_account` und `machine_hashes`.
  Sie sind die Voraussetzung fuer den Domainkonto-Modus; die CLI des Agenten
  bietet sie noch nicht an — der Aufrufer setzt `domain: None`.
- **Angriffsspflaeche:** Mit dem Fix startet der Relay tatsaechlich. Er
  lauscht dann auf `0.0.0.0:445` des Agenten-Hosts. Im Testnetz (Kali-VM
  192.168.191.142 im libvirt-Netz) ist das eingegrenzt, aber es bleibt eine
  Tatsache: Der Agenten-Host lauscht waehrend des Versuchs auf SMB.
- **Zeitgrenze:** `RELAY_TIMEOUT` steht auf 120 s. Das Relay-Skript lauscht
  weiter, wenn sich kein Opfer authentifiziert. Bei einem Scan ueber ein
  /24-Netz bedeutet das 254 Hosts mal 120 s. Die Grenze ist nicht geaendert
  worden — sie ist eine Design-Entscheidung (vgl. ADR-0003 zur Zeitgrenze des
  Task-Kanals) und gehoert in eine eigene Entscheidung, nicht in diesen Fix.
- `ExploitError` bekommt die Variante `Configuration` fuer unvollstaendige
  Konfiguration; `ImpacketMissing` und `NoResult` passen semantisch nicht.
- Related: ISSUE-2 (SMB-Relay toter Code), ISSUE-3 (Default-Credentials toter
  Code)
