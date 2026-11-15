# Epic: C2-Operability — der Kx-Stack ist derzeit nicht durchgängig lauffähig

**Stand:** 2026-11-11
**Quelle:** EGM Drift Report (`2026-11-11_DRIFT_REPORT.md`) — 12 Code-Bugs, aufgedeckt durch 10 unabhängige Reviewer in frischem Kontext, eine Regenerations-Runde gegen den umgebauten Code und ein Start-Smoke-Test. Zwei weitere Befunde (ISSUE-12, ISSUE-13) kamen bei der Verifikation des Design-Entwurfs hinzu.
**Design-Entwurf:** `design_draft.md` (1434 Zeilen) — CUJs, Zwei-Wellen-Plan, Entscheidungen D1–D7, Alternativen, Non-Functional Requirements.

## Kurzfassung

Die Contracts sind inzwischen gegen den aktuellen Code geprüft und korrigiert. Die Code-Prüfung hat dabei dreizehn Stellen aufgedeckt, an denen der dokumentierte Betriebsablauf **nicht funktioniert**. Die sechs schwersten sind:

- Der C2-Server startet überhaupt nicht (ISSUE-1) — der gesamte Ablauf ist blockiert.
- Die C2-API erzwingt keine Authentifizierung (ISSUE-12) — wer den Port erreicht, liest die gesamte Beute.
- Das Dashboard rendert Beutefelder ohne Escaping (ISSUE-13) — gespeichertes XSS im Browser des Operators.
- Die Linux-Persistenz startet das Binary ohne Argumente und läuft in eine Neustart-Schleife (ISSUE-10).
- Beide Exploit-Pfade des Agenten sind toter Code (ISSUE-2, ISSUE-3).
- Die Post-Quantum-Verschlüsselung der Beute ist nicht aktiv (ISSUE-9).

## Issues

| ID | Titel | Priorität | Status |
|----|-------|-----------|--------|
| [ISSUE-1](issues/ISSUE-1-server-startet-nicht.md) | kx-server startet nicht — mehrdeutige rustls-CryptoProvider-Auflösung | high | done |
| [ISSUE-12](issues/ISSUE-12-api-ohne-authentifizierung.md) | C2-API ist nicht authentifiziert — jeder mit Netzzugang liest die Beute | high | done |
| [ISSUE-13](issues/ISSUE-13-dashboard-xss-und-token-im-query-string.md) | Dashboard rendert API-Werte ohne Escaping — gespeichertes XSS; Token im Query-String | high | done |
| [ISSUE-9](issues/ISSUE-9-post-quantum-verschluesselung-inaktiv.md) | Post-Quantum-Verschlüsselung der Beute ist inaktiv — hostkey-Modul nicht kompiliert | high | open |
| [ISSUE-10](issues/ISSUE-10-systemd-neustartschleife.md) | systemd-Unit startet das Binary ohne Argumente — Neustart-Schleife bei Restart=always | high | done |
| [ISSUE-2](issues/ISSUE-2-smb-relay-toter-code.md) | SMB-Relay ist toter Code — Port 445 fehlt in COMMON_PORTS | high | done |
| [ISSUE-3](issues/ISSUE-3-default-credentials-toter-code.md) | Default-Credential-Angriff ist toter Code — try_default_credentials liefert stets Ok(None) | high | open |
| [ISSUE-4](issues/ISSUE-4-credential-manager-einzelnes-credential.md) | extract_credential_manager liefert bei genau einem Credential eine leere Liste | medium | open |
| [ISSUE-6](issues/ISSUE-6-tasks-tabelle-ungenutzt.md) | GET /api/tasks liefert immer [] — Db::insert_task hat keinen Aufrufer | medium | done |
| [ISSUE-7](issues/ISSUE-7-wmi-exec-ohne-aufrufer.md) | wmi_exec hat keinen Aufrufer — dokumentierter WMI-Angriffspfad existiert nicht | medium | done |
| [ISSUE-8](issues/ISSUE-8-ml-kem-pin-umgangen.md) | ml-kem-Pin im Workspace wird von kx-core umgangen — 0.2.3 wird aufgelöst | medium | done |
| [ISSUE-11](issues/ISSUE-11-token-im-debug-output.md) | Args leitet Debug ab — das C2-Token landet in jeder Debug-Ausgabe | medium | open |
| [ISSUE-5](issues/ISSUE-5-demo-worm-range-flag.md) | demo_worm.rs Nutzungskommentar nennt nicht existierendes Flag --range | low | open |

## Empfohlene Reihenfolge

Die Wellen aus `design_draft.md` sind die verbindliche Reihenfolge.

**Welle 1 — Betrieb herstellen:**

1. **ISSUE-1** — ohne lauffähigen Server ist nichts weiter testbar. Der Fix ist verifiziert: `axum-server` auf `tls-rustls-no-provider` umstellen, `aws-lc-rs` verschwindet dann aus dem Lockfile, und der Server startet und antwortet mit der API-Übersicht.
2. **ISSUE-12** — direkt danach. Ein startender, ungeschützter C2-Server ist ein schlimmerer Zustand als ein nicht startender; die Beute aller erbeuteten Hosts liegt im Klartext für jeden lesbar, der den Port erreicht.
3. **ISSUE-13** — im selben Zug wie ISSUE-12. Das Dashboard rendert API-Werte per `innerHTML` ohne Escaping (verifiziert: ein Host mit `<img src=x onerror=…>` im `hostname` erscheint als ausführbares Markup), und das Token steht im Query-String. Das Escaping ist **Vorbedingung** für das HTML-Login aus D2: sobald das Token im Arbeitsspeicher des Browsers liegt, kann ein injiziertes Skript es auslesen. Details in der Issue-Datei.
4. **ISSUE-10** — die Persistenz ist der Zweck des Agenten; die aktuelle Unit startet ihn garantiert nie durch.
5. **ISSUE-8** — Voraussetzung für ISSUE-9. Die Form des Fixes ist trivial (`workspace = true`), die Version nicht: der Pin muss auf **`=0.2.3`** stehen — `=0.2.1` bricht den Build (verifiziert, 18 Compile-Errors in `ml-kem` selbst). Details in der Issue-Datei.
6. **ISSUE-9** — stellt die im Kern versprochene Eigenschaft wieder her: die Beute wird verschlüsselt transportiert. Achtung: größer als zunächst beschrieben — die von `hostkey.rs` verwendete `ml-kem`-API existiert in **0.2.1, 0.2.3 und auch 0.1.1 nicht**. Der Pin-Fix allein bringt nichts, das Modul muss auf eine vorhandene API umgeschrieben werden. Ein Prototyp gegen 0.2.1 kompiliert und läuft bereits.

**Welle 2 — Funktionslücken schließen:**

7. **ISSUE-2 + ISSUE-3** — machen die beiden Exploit-Pfade wieder ausführbar. Für ISSUE-2 heißt das mehr als den Port-Fix: das referenzierte Relay-Skript liegt nicht im Repository, der Pfad scheitert also auch mit Port 445 an einer fehlenden Datei.
8. **ISSUE-4** — Korrektheit der Credential-Extraktion, betrifft ein einzelnes gespeichertes Credential.
9. **ISSUE-7** — der WMI-Pfad wird entfernt statt verdrahtet (Entscheidung vom 2026-11-15). ISSUE-6 ist erledigt (PR #8, Commit `209834e`): Task-Anlage, Agent-Abholung und -Rückmeldung liegen in `origin/main`.
10. **ISSUE-11** — Token-Härtung, unkritisch aber billig.
11. **ISSUE-5** — kosmetisch, aber triviales Doc-Fix.

## Abhängigkeiten

- ISSUE-1 ist Voraussetzung für die Verifikation aller anderen Issues (kein Server, kein End-to-End-Test) und für ISSUE-12 im Besonderen.
- ISSUE-8 ist Voraussetzung für ISSUE-9.
- ISSUE-10 und ISSUE-9 hängen fachlich zusammen: die Unit-Datei braucht Argumente, die ein lauffähiger Agent liefern muss — mit ISSUE-9 aktiv ist zusätzlich der Master-Key pro Host nötig.
- ISSUE-2 und ISSUE-7 teilen sich die Scan-Port-Problematik: der Exploit-Pfad braucht eigene Ports (445, 5985/5986), die nicht in `COMMON_PORTS` liegen.
- ISSUE-6 und ISSUE-7 betreffen beide den `Task`-Typ in `kx_core::c2` — die Route und die Agent-Seite gehören in dieselbe Welle.
- ISSUE-11 betrifft `kx-agent` und `kx-cli` gleichermaßen.
- ISSUE-12 und ISSUE-13 gehören in dieselbe Umstellung: das Dashboard bekommt ein HTML-Login-Formular, und die API-Werte werden vor dem Einsetzen escapet (Entscheidungen D1 und D2 in `design_draft.md`). Das Escaping ist dabei keine Nebensache, sondern Vorbedingung — ohne Escaping verschlechtert die Token-Verlagerung in den Browser die Lage.

## Verifikation nach der Welle

```bash
cd /Volumes/T7/Projekte/testwurm/kx
cargo test --workspace          # aktuell 47 Tests grün, 0 Fehler
cargo build --release
./target/release/kx-server --host 127.0.0.1 --port 8443 --db /tmp/kx.db --token test
```

Der Start-Smoke-Test ist der eigentliche Abnahmeprüfpunkt: er schlägt heute mit dem CryptoProvider-Panic fehl und muss nach ISSUE-1 mit der API-Übersicht antworten.

## Triage-Stand (2026-11-15)

Der Tracker war nicht mit `origin/main` synchron. Verifikation gegen `origin/main`
(74 Tests grün) ergab:

- **ISSUE-6 ist erledigt** — PR #8, Commit `209834e`. Der Agent-Brief entfällt.
- **ISSUE-2 ist nur halb behoben** — Port 445 ist im Code, das referenzierte
  Relay-Skript fehlt im Repository. Scope erweitert.
- **ISSUE-3, ISSUE-4, ISSUE-5, ISSUE-11, ISSUE-14** sind erledigt (PR #21 und
  PR #22), **ISSUE-7** ebenfalls — der WMI-Pfad wurde entfernt statt verdrahtet.
- **ISSUE-2 und ISSUE-9** sind `ready-for-agent`. Für die zwei verbleibenden
  Issues liegt je ein Agent-Brief unter [`briefs/`](briefs/), die Entscheidungen
  vom 2026-11-15 sind in den jeweiligen Triage Notes festgehalten.

Nicht von einem Issue abgedeckt: der lokale Branch `fix/welle-1-operability`
war gegenüber `origin/main` diverged und ist archiviert.
