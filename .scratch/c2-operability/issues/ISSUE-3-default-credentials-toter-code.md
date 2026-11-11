---
id: ISSUE-3
title: Default-Credential-Angriff ist toter Code — try_default_credentials liefert stets Ok(None)
status: open
priority: high
---

## Description

Der in `kx/README.md` dokumentierte Angriffspfad „SSH-Systeme mit Default-Credentials testen" ist implementiert, kann aber **kein Ergebnis** erzeugen.

`kx_exploit::try_default_credentials` (`kx-exploit/src/credential_stuff.rs:40-47`) iteriert über `DEFAULT_CREDENTIALS` (sechs fest verdrahtete Paare: `admin/admin`, `admin/password`, `root/root`, `test/test`, `Administrator/Administrator`, `pi/raspberry`), führt aber **keinen echten Authentifizierungsversuch** durch und gibt stets `Ok(None)` zurück. Der Codekommentar bezeichnet das ausdrücklich als Platzhalter.

Damit greift der Zweig `if let Ok(Some(auth)) = ...` in `kx-agent/src/propagate.rs:106` nie, und es entsteht kein Secret mit `cred_type` `"password"` / `source` `"default_creds"`. Dieselbe Einschränkung gilt für das Beispiel-Binary `kx-exploit/examples/demo_worm.rs:116`.

Zusätzlich: `DEFAULT_CREDENTIALS` ist ein `&[(&str, &str)]` ohne Dienstangabe — die Funktion erhält `host` und `service` als Parameter, verwendet die Credentials aber nicht.

Related: ISSUE-2, ISSUE-4

## Acceptance Criteria

- [ ] `try_default_credentials` führt einen echten Authentifizierungsversuch durch und liefert bei Erfolg `Ok(Some(Auth))`. Bevorzugt `russh` 0.54 mit `features = ["ring"]`: reines Rust, `rand_core` 0.6.4 wie der Workspace, und Client **und** Server für den Mock-SSH-Test. `ssh2` würde die C-Toolchain (libssh2) ins Build ziehen, `paramiko` wäre Python. Begründung und verworfene Alternativen: `design_draft.md`, D4 und Alternative G.
- [ ] Bei Misserfolg wird `Ok(None)` zurückgegeben und **kein** Fehler — das Verhalten bleibt für Aufrufer unkritisch
- [ ] Der Dienst wird berücksichtigt (die Credentials gelten für SSH, nicht für beliebige Dienste)
- [ ] Ein Test prüft den Erfolgs- und den Misserfolgsfall gegen einen lokalen Mock-SSH-Dienst

## Technical Notes

- Betroffen: `kx/crates/kx-exploit/src/credential_stuff.rs:40-47`
- Der Agent ruft die Funktion nur bei `service == "ssh"` auf (`propagate.rs:105`) — der Pfad ist also fachlich richtig verdrahtet, nur die Funktion ist ein Stub
- `Auth` trägt `username`, `password`, `service` — die Felder passen zum geplanten Ergebnis
- Sicherheitsaspekt: Default-Credentials gegen fremde Hosts sind ohne Autorisierung rechtlich problematisch. Das Repo ist explizit auf autorisierte Tests ausgerichtet (`CLAUDE.md`, `kx/README.md`); die Implementierung sollte einen Scope-Parameter vorsehen, damit sie nicht versehentlich außerhalb des Testnetzes läuft
