---
id: ISSUE-7
title: wmi_exec hat keinen Aufrufer — dokumentierter WMI-Angriffspfad existiert nicht
status: done
category: bug
triage_state: erledigt
agent_brief: briefs/ISSUE-7-wmi-pfad-entfernen.md
priority: medium
---

## Description

`kx_exploit::wmi_exec` ist implementiert (`kx-exploit/src/wmi_exec.rs`) und wird aus dem Crate exportiert (`kx-exploit/src/lib.rs:20`), hat aber **keinen Aufrufer** im gesamten Workspace:

- Der Agent (`kx-agent/src/propagate.rs`) importiert `smb_relay_dcsync` und `try_default_credentials`, aber nicht `wmi_exec`.
- Das Beispiel-Binary `kx-exploit/examples/demo_worm.rs` importiert es ebenfalls nicht.
- Das CLI-Flag `--wmi-script` des Agenten wird geparst, aber nie ausgewertet.

Damit ist der in `kx/README.md` dokumentierte WMI-/WinRM-Exploit-Pfad reine Wunschdokumentation. Zusätzlich fehlt dem Agenten damit der zweite Exploit-Pfad neben dem ohnehin toten SMB-Relay (ISSUE-2).

Related: ISSUE-2, ISSUE-6

## Acceptance Criteria## Acceptance Criteria

- [ ] Der WMI-Ausführungspfad ist entfernt: das Flag `--wmi-script`, der Parameter in `run_propagation` und das Modul `wmi_exec` existieren nicht mehr
- [ ] Der Exploit-Crate exportiert keinen WMI-Ausführungspfad mehr
- [ ] Betriebshandbuch, Crate-READMEs, Blueprint und die Agenten-Konfiguration nennen den WMI-Pfad nicht mehr als vorhanden

## Technical Notes

- Betroffen: `kx-exploit/src/wmi_exec.rs` (Implementierung, vorhanden), `kx-agent/src/propagate.rs` (kein Aufruf), `kx-agent/src/main.rs` (`--wmi-script` geparst, ungenutzt)
- Zwei Wege: Implementierung anschließen oder die irreführende Dokumentation entfernen. Die erste Variante ist sinnvoller, weil die Funktion bereits existiert und getestet werden kann
- WMI-Ausführung benötigt Port 5985/5986 (WinRM) — diese Ports müssten in den Scan einbezogen werden, was ISSUE-2 berührt
- Das Passwort wird bei `wmi_exec` als Kommandozeilenargument übergeben (`format!("{}{}", domain, username)`) — im Prozess-Listing sichtbar, ein Sicherheitsdetail für die Zielsysteme

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der Befund ist bestätigt: der WMI-Ausführungspfad des Exploit-Crates hat keinen
  Aufrufer, das Agenten-Flag wird geparst, aber nie ausgewertet, und die
  Betriebsdokumentation beschreibt den Pfad als vorhanden.
- Wie ISSUE-2 fehlt auch hier das referenzierte WMI-Skript im Repository.

**Triage-Entscheidung:** Der Maintainer hat am 2026-11-15 entschieden, den
WMI-Pfad zu entfernen statt ihn anzubinden — das ist der in der Issue
ausdrücklich zugelassene zweite Weg. Agent Brief: [`briefs/ISSUE-7-wmi-pfad-entfernen.md`](briefs/ISSUE-7-wmi-pfad-entfernen.md)

**Erledigt am 2026-11-15:** Der WMI-Pfad wurde entfernt statt verdrahtet — Entscheidung des Maintainers vom 2026-11-15. Das Modul `wmi_exec` ist gelöscht, der Exploit-Crate exportiert die WMI-Typen nicht mehr, das Agenten-Flag `--wmi-script` und der Parameter in `run_propagation` sind weg, das Beispiel-Binary kennt das Flag nicht mehr. Betriebshandbuch, Crate-READMEs, Blueprint, `CLAUDE.md` und `AGENTS.md` nennen den Pfad nicht mehr.
