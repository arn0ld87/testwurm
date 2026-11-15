---
id: ISSUE-14
title: Agent hängt im SSH-Default-Credential-Test — sshpass ohne Timeout
status: open
category: bug
triage_state: ready-for-agent
agent_brief: briefs/ISSUE-14-ssh-credential-test-timeout.md
priority: high
---

## Description

Der Agent bleibt im SSH-Zweig von `run_propagation` **unbegrenzt** hängen,
wenn auf dem Ziel Port 22 offen ist und `sshpass` installiert ist.

`kx_exploit::try_default_credentials` (`kx-exploit/src/credential_stuff.rs:45`)
startet pro Credential-Kombination:

```
sshpass -f - ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 <user>@<host> true
```

und wartet mit `child.wait()` auf das Ergebnis. Zwei Probleme:

1. **`ConnectTimeout=3` deckt nur den TCP-Handshake ab.** Für die
   Authentifizierungsphase (Passwort-Prompt, Retry-Schleife von `ssh`) gibt es
   keinen Timeout. Hängt der SSH-Server oder antwortet er nicht mit einem
   Passwort-Prompt, wartet `sshpass` endlos.
2. **`-f -` (Passwort von stdin) wird nicht von jeder `sshpass`-Version
   unterstützt.** Der Homebrew-Build 1.10 auf macOS meldet
   `SSHPASS: Failed to open password file "-": No such file or directory` und
   bleibt anschließend hängen. Auf dem Agenten-Host ist `sshpass` also nicht
   nur optional, sondern eine **Hänge-Quelle**, sobald Port 22 offen ist.

Verifiziert am 2026-11-15 auf dem macOS-Host mit `kx-agent` gegen den lokalen
C2-Server (`--hosts 127.0.0.1`):

```
INFO kx_agent: Kx-Agent startete, C2=https://localhost:18444
INFO kx_agent: 2 lokale Secrets extrahiert und hochgeladen
ERROR kx_agent: Persistenz-Installation fehlgeschlagen: systemd-Fehler: Permission denied (os error 13)
INFO kx_agent: Nutze vorgegebene Host-Liste
INFO kx_agent::propagate: TCP-Scan auf 1 Hosts
INFO kx_agent::propagate: Offener Port 22 auf 127.0.0.1 (ssh)
   ← ab hier kein weiterer Log-Eintrag, Prozess läuft > 3 Minuten
```

Der Prozessblock zeigt den Wartezustand:

```
main → kx_agent::main → kx_agent::propagate::run_propagation → __wait4
```

Der Kindprozess ist `sshpass -f - ssh -o StrictHostKeyChecking=no
-o ConnectTimeout=3 admin@127.0.0.1 true`.

Nebenwirkung: Der Agent meldet seine Ergebnisse **nicht** an den C2-Server,
weil er die Phase „Report" nie erreicht. Der Lauf ist damit wertlos, aber der
Prozess belegt Ressourcen.

Related: ISSUE-3

## Acceptance Criteria

- [ ] Der SSH-Default-Credential-Test hat ein **Gesamt-Timeout** (Vorschlag:
      `timeout 10` pro Kombination, Abbruch nach spätestens 60 s für alle
      sechs Kombinationen)
- [ ] Der Timeout ist so gewählt, dass ein hängender `sshpass` den Agentenlauf
      nicht blockiert; der Agent beendet sich regulär und meldet seine Ergebnisse
- [ ] Ein Fehlerfall (`sshpass` nicht installiert, `-f -` nicht unterstützt,
      Timeout abgelaufen) führt zu einem kontrollierten Fehler, nicht zu einem
      Hänger
- [ ] Ein Test prüft den Timeout-Fall (Mock-SSH-Dienst, der nicht antwortet)
- [ ] Die Dokumentation nennt die Abhängigkeit `sshpass` mit korrekter
      Versionserwartung und den Workaround `timeout` für den Agentenlauf

## Technical Notes

- Betroffen: `kx/crates/kx-exploit/src/credential_stuff.rs:45-81`
- Aufrufer: `kx/crates/kx-agent/src/propagate.rs:108` (nur wenn
  `service == "ssh"`, also bei offenem Port 22)
- `DEFAULT_CREDENTIALS` umfasst sechs fest verdrahtete Paare (Konstante in
  `kx/crates/kx-exploit/src/credential_stuff.rs`) — ohne Timeout sind das bis zu
  sechs unabhängige Hänger
- Workaround bis zur Behebung: den Agentenlauf in eine `timeout`-Hülle setzen
  (`timeout 300 ./kx-agent …`) oder Ziele ohne offenen Port 22 wählen

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (63 Tests grün):**

- Der Befund ist bestätigt: der Subprozess wird ohne Zeitgrenze und ohne
  Abbruchmechanismus erwartet. Die gesetzte Verbindungs-Zeitgrenze greift nur
  für den Verbindungsaufbau; ein danach hängender Prozess blockiert den
  Agentenlauf endlos. Die Kandidaten laufen sequenziell, die Wartezeit summiert
  sich.
- Der Doc-Kommentar des Moduls verspricht bereits ein Zeitlimit, das der Code
  nicht setzt.

**Triage-Entscheidung:** Der Maintainer hat am 2026-11-15 entschieden, `sshpass`
beizubehalten und die Zeitgrenze obendrauf zu setzen. Agent Brief: [`briefs/ISSUE-14-ssh-credential-test-timeout.md`](briefs/ISSUE-14-ssh-credential-test-timeout.md)
