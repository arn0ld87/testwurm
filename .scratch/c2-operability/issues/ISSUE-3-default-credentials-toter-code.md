---
id: ISSUE-3
title: Default-Credential-Angriff ist toter Code — try_default_credentials liefert stets Ok(None)
status: done
category: bug
triage_state: erledigt
agent_brief: briefs/ISSUE-3-credential-test-dienstfilter.md
priority: high
---

## Description

Der in `kx/README.md` dokumentierte Angriffspfad „SSH-Systeme mit Default-Credentials testen" ist implementiert, kann aber **kein Ergebnis** erzeugen.

`kx_exploit::try_default_credentials` (`kx-exploit/src/credential_stuff.rs:40-47`) iteriert über `DEFAULT_CREDENTIALS` (sechs fest verdrahtete Paare: `admin/admin`, `admin/password`, `root/root`, `test/test`, `Administrator/Administrator`, `pi/raspberry`), führt aber **keinen echten Authentifizierungsversuch** durch und gibt stets `Ok(None)` zurück. Der Codekommentar bezeichnet das ausdrücklich als Platzhalter.

Damit greift der Zweig `if let Ok(Some(auth)) = ...` in `kx-agent/src/propagate.rs:106` nie, und es entsteht kein Secret mit `cred_type` `"password"` / `source` `"default_creds"`. Dieselbe Einschränkung gilt für das Beispiel-Binary `kx-exploit/examples/demo_worm.rs:116`.

Zusätzlich: `DEFAULT_CREDENTIALS` ist ein `&[(&str, &str)]` ohne Dienstangabe — die Funktion erhält `host` und `service` als Parameter, verwendet die Credentials aber nicht.

Related: ISSUE-2, ISSUE-4

## Acceptance Criteria## Acceptance Criteria

- [x] `try_default_credentials` führt einen echten Authentifizierungsversuch durch und liefert bei Erfolg `Ok(Some(Auth))`. Der Werkzeugansatz ist `sshpass` — Entscheidung des Maintainers vom 2026-11-15; die ursprünglich vorgesehene rein-Rust-Bibliothek ist damit nicht mehr bindend.
- [x] Bei Misserfolg wird `Ok(None)` zurückgegeben und **kein** Fehler — das Verhalten bleibt für Aufrufer unkritisch
- [x] Der Dienst wird berücksichtigt (die Credentials gelten für SSH, nicht für beliebige Dienste)
- [x] Ein Test deckt den Erfolgs- und den Misserfolgsfall ab

## Technical Notes

- Betroffen: `kx/crates/kx-exploit/src/credential_stuff.rs:40-47`
- Der Agent ruft die Funktion nur bei `service == "ssh"` auf (`propagate.rs:105`) — der Pfad ist also fachlich richtig verdrahtet, nur die Funktion ist ein Stub
- `Auth` trägt `username`, `password`, `service` — die Felder passen zum geplanten Ergebnis
- Sicherheitsaspekt: Default-Credentials gegen fremde Hosts sind ohne Autorisierung rechtlich problematisch. Das Repo ist explizit auf autorisierte Tests ausgerichtet (`CLAUDE.md`, `kx/README.md`); die Implementierung sollte einen Scope-Parameter vorsehen, damit sie nicht versehentlich außerhalb des Testnetzes läuft

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der tote Code ist beseitigt: es existiert ein echter Authentifizierungsversuch,
  der bei Erfolg einen Treffer liefert und bei Misserfolg kontrolliert `None`.
- Offen bleibt der Dienstparameter: er wird entgegengenommen, aber nicht
  ausgewertet. Jeder Aufruf versucht SSH, unabhängig vom angesprochenen Dienst.
- Offen bleibt der Timeout (eigene Issue) und ein Test.

**Triage-Entscheidung:** Der Maintainer hat am 2026-11-15 entschieden, den
Werkzeugansatz `sshpass` beizubehalten und den Timeout obendrauf zu setzen. Die
ursprüngliche Vorgabe einer reinen Rust-SSH-Bibliothek mit Mock-Server im Test
ist damit nicht mehr bindend; die Akzeptanzkriterien wurden entsprechend
angepasst. Agent Brief: [`briefs/ISSUE-3-credential-test-dienstfilter.md`](briefs/ISSUE-3-credential-test-dienstfilter.md)

**Erledigt am 2026-11-15:** Der Dienstfilter greift jetzt in `try_default_credentials` selbst — nur `ssh` löst einen Versuch aus, jeder andere Dienst liefert kontrolliert `Ok(None)`, ohne einen Prozess zu starten. Der Versuch läuft über `sshpass`, das Passwort geht als eine Zeile über stdin. Sechs Tests decken Dienstfilter, Erfolgs-, Misserfolgs- und Fehlerfall ab. Der Erfolgstest simuliert den gelungenen Login über einen Befehl statt über einen echten SSH-Server — der Test prüft das beobachtbare Verhalten, nicht die Werkzeugkette.
