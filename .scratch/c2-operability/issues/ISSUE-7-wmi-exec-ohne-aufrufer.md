---
id: ISSUE-7
title: wmi_exec hat keinen Aufrufer — dokumentierter WMI-Angriffspfad existiert nicht
status: open
category: bug
triage_state: ready-for-agent
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

## Acceptance Criteria

- [ ] Der Agent ruft `wmi_exec` für erreichbare Windows-Ziele auf, oder das Flag `--wmi-script` und der Contract werden entfernt
- [ ] Die Fehlerbehandlung ist dokumentiert: `wmi_exec` erzeugt `ExploitError::SubprocessFailed` **nie**, ein Fehlschlag landet ausschließlich in `ExecResult.exit_code` (`wmi_exec.rs:66-70`)
- [ ] Der Pfad ist im Contract-README als aktiv dokumentiert, nicht als vorhandene Funktion

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
