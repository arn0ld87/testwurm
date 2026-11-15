# Agent Brief — ISSUE-7

**Category:** bug
**Summary:** Der dokumentierte WMI-Exploit-Pfad existiert nicht; das Agenten-Flag dafür wird geparst, aber nie ausgewertet.

**Current behavior:**
Das Exploit-Crate stellt einen WMI-Ausführungspfad bereit, den niemand aufruft. Der
Agent parst ein Flag für das WMI-Skript, reicht es aber als ungenutzten Parameter
weiter und wertet es nie aus. Die Betriebsdokumentation beschreibt den Pfad als
vorhanden. Zusätzlich existiert das referenzierte WMI-Skript nirgends im
Repository — auch der SMB-Pfad hat dieses Problem, dort ist es aber getrennt
erfasst (ISSUE-2).

**Desired behavior:**
Es gibt genau eine Aussage: entweder der WMI-Pfad ist nutzbar oder er existiert
nicht. Der Maintainer hat am 2026-11-15 entschieden: **der WMI-Pfad wird entfernt** —
Flag, Aufrufstelle, Exporte und Dokumentationsaussagen. Der SMB-Relay-Pfad bleibt als
einziger Exploit-Pfad erhalten.

**Key interfaces:**
- Das CLI-Flag des Agenten für das WMI-Skript: entfällt vollständig, auch als Alias.
- `run_propagation()`: der ungenutzte Parameter für das WMI-Skript entfällt; die
  aufrufende Stelle im Agenten-Entry-Point übergibt ihn nicht mehr.
- `wmi_exec()`, `ExecConfig`, `ExecResult` im Exploit-Crate: Exporte und Modul
  entfallen.
- Crate-README, Betriebshandbuch und Glossar: Aussagen zum WMI-Pfad werden auf den
  verbleibenden Stand gebracht.

**Acceptance criteria:**
- [ ] Das Agenten-Flag für das WMI-Skript existiert nicht mehr
- [ ] Der Exploit-Crate exportiert keinen WMI-Ausführungspfad mehr
- [ ] `run_propagation()` nimmt keinen WMI-Skript-Parameter mehr entgegen, und die
      aufrufende Stelle übergibt ihn nicht mehr
- [ ] Betriebshandbuch, Crate-README und Glossar nennen den WMI-Pfad nicht mehr als
      vorhanden
- [ ] Der Workspace baut und die Test-Suite ist grün

**Out of scope:**
- Der SMB-Relay-Pfad (ISSUE-2)
- Der Credential-Stuffing-Pfad (ISSUE-3, ISSUE-14)
- Ein Ersatz für den entfernten Pfad
