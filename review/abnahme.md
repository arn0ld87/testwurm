# Abnahme-Review · Testwurm-Präsentations-Demo

- Datum: 2026-11-25, Reviewer (unabhängige Abnahme)
- Artefaktbasis: `/Volumes/T7/Projekte/testwurm` (Git HEAD `a483d2d`)
- Live-Gegenprüfung: Orchestrator auf `http://127.0.0.1:8321` (nur GET, wie vorgeschrieben)
- Umfang: 9 Prüfkriterien; keine Fixes versucht, nur Befunde gemeldet.

## Gesamtergebnis

**BESTANDEN mit Nachlässigkeiten (keine Blocker).**
Alle 9 Kriterien PASS. 4 leichte Befunde (Doku-Alttext im API-Contract, kaputte
Log-Zeitstempel, `make clean-lab` vergisst den C2-Container, Contract-Endpunkt
`/api/scenarios` von der GUI ungenutzt) und 2 Sicherheits-Hinweise (Netz nicht
`--internal`, Dateirechte des Server-Private-Keys) —详见 Befunde.

| # | Kriterium | Status | Evidenz |
|---|---|---|---|
| 1 | GUI (index.html + app.js + styles.css) | **PASS** | s. Detail 1 |
| 2 | Fehlerresistenz | **PASS** | s. Detail 2 |
| 3 | Offline (keine CDNs/Fonts, keine npm-Deps, kein Build) | **PASS** | s. Detail 3 |
| 4 | API-Contract konsistent | **PASS** (Befund B1/B4) | s. Detail 4 |
| 5 | Start: start.sh / Makefile / package.json | **PASS** (Befund B3) | s. Detail 5 |
| 6 | Labor-Sicherheit | **PASS** (Hinweise H1/H2) | s. Detail 6 |
| 7 | Doku: DEMO_SCRIPT / SETUP_LOG | **PASS** (Befund B2, unsicher U1) | s. Detail 7 |
| 8 | Tests ausgeführt und protokolliert | **PASS** (7/7 grün) | s. Detail 8 |
| 9 | Live-Zustand API | **PASS** | s. Detail 9 |

---

## Detailprüfungen

### Kriterium 1 — GUI · PASS

| Teilforderung | Beleg |
|---|---|
| Deutsche Oberfläche | `public/index.html:2` (`lang="de"`), Titel/Buttons/Labels deutsch (Zeilen 6, 14, 30–33, 46) |
| Status-Banner ≥ 28px | `public/styles.css:103` `.status-banner { font-size: var(--font-size-2xl) }`, Token `--font-size-2xl: 32px` (`styles.css:48`) → 32px ≥ 28px |
| Buttons ≥ 18px Schrift | `styles.css:197` `.btn { font-size: var(--font-size-lg) }`, Token `--font-size-lg: 18px` (`styles.css:46`) |
| Buttons ≥ 64px Höhe | `styles.css:200` `.btn { min-height: 64px }` |
| Start/Pause/Einzelschritt/Reset Demo | `index.html:30–33` — alle vier Buttons vorhanden |
| 3 Szenario-Karten | `index.html:39–49` — happy-path / error-recovery / full-traversal |
| Banner-Texte Bereit/Läuft/Pausiert/Abgeschlossen/Fehler abgefangen | `orchestrator/lib.mjs:72–78` `BANNER`-Map deckt exakt diese fünf Texte ab; GUI übernimmt `state.banner` (`app.js:120–126`); CSS-Klassen für alle Status: `styles.css:110–137` (inkl. `.status-error_contained`) |
| SVG-Graph | `index.html:63–67` + `app.js:239` (`renderGraph`) |
| Architektur-Tab | `index.html:55–57` (Tab-Buttons), `app.js:105–115` (`fetchArchitecture`), `app.js:349` (`renderArchitectureGraph`) |
| Kontext-Panel mit savedPct + Telemetrie | `index.html:84–85` (`saved-pct`), `index.html:106–124` (Telemetrie-Grid); Datenpfad `app.js:141–165`,契约-Felder `rawTokens/keptTokens/summaries/savedPct` live bestätigt (GET /api/state) |
| Live-Log mit einklappbaren Details | `app.js:198–205` (Click → `toggle('expanded')`), `styles.css:500–510` (`.log-detail { display:none }` / `.expanded .log-detail { display:block }`) |
| Tastatur Leertaste/S/R | `app.js:524` (`' '` → Start/Pause), `app.js:532` (`s/S` → Einzelschritt), `app.js:537` (`r/R` → Reset); Eingabefelder ausgenommen (`app.js:521`) |

Hinweis: Prüfung statisch (Code/CSS-Werte) — kein visueller Browser-Screenshot
(Befund-Umfang U2).

### Kriterium 2 — Fehlerresistenz · PASS

- `window.onerror` → rotes Banner mit exaktem Text: `app.js:57–61`
  (`showErrorBanner('Fehler abgefangen – Oberfläche bleibt bedienbar')`),
  Banner-Styling rot: `styles.css:141–146` (`.error-banner { background: --color-failed }`);
  Log-Eintrag zusätzlich (`app.js:59`); Rückgabe `true` unterdrückt Default-Handling.
- Unhandled Rejections abgefangen: `app.js:63–67` (`window.onunhandledrejection`,
  HTML-Spec-Handler auf Window, identischer Banner-Text).
- Fetch-Fehler /api/state → `'Verbindung zum Server verloren – Reconnect läuft'`:
  `app.js:76–78`; Polling läuft weiter, da `poll()` den Timer unbedingt neu setzt
  (`app.js:567–572`, POLL_INTERVAL 400 ms) und der Fehlerweg `null` liefert, statt
  zu throwen.
- Steuerungsfehler (POST /api/control) fangen ebenfalls ab (`app.js:99–102`),
  Oberfläche bleibt bedienbar; Banner blendet nach 5 s automatisch aus (`app.js:44–50`).

### Kriterium 3 — Offline · PASS

- Keine externen URLs/CDNs/Fonts in `public/`: `grep -nE 'https?://' public/*`
  liefert nur den SVG-Namespace `http://www.w3.org/2000/svg` in `app.js`
  (createElementNS, explizit erlaubt); `styles.css:43` nutzt nur System-Font-Stack.
  `index.html` referenziert ausschließlich `styles.css` und `app.js` (Zeilen 7, 139).
- Keine npm-Abhängigkeiten: `package.json` enthält keinerlei `dependencies`/
  `devDependencies`-Feld (Datei geprüft, 13 Zeilen); Orchestrator nutzt nur
  Node-Built-ins (`server.mjs:17–22`, Header-Kommentar Zeile 15 „Keine npm-Abhängigkeiten“).
- Kein Build-Schritt für die GUI: `public/` wird statisch ausgeliefert
  (`server.mjs:388–395`); `start.sh` führt nur den einmaligen Rust-Build der
  Labor-Binaries aus (`start.sh:23–29`), die GUI selbst ist unverändert lauffähig.

### Kriterium 4 — API-Contract · PASS mit Befunden B1, B4

Verglichen: `docs/API_CONTRACT.md` ↔ `orchestrator/server.mjs` ↔ `public/app.js`.

- `GET /api/state` → `{ok:true,state:{…}}`: `server.mjs:367–368` ↔ `app.js:71–74`.
  Zustandsform vollständig gegen Contract geprüft (runStatus, scenarioId,
  scenarioName, seed, tick, totalStepsPlanned, worm, nodes, edges, log, context,
  telemetry, banner) — live bestätigt via GET (Detail 9).
- `POST /api/control` mit `start|pause|step|reset` + `scenarioId`:
  `server.mjs:373–397` validiert gegen dieselbe Aktionenliste; Antwort-Envelope
  identisch (`server.mjs:396`); Fehlerweg 400 mit `ok:false` (`server.mjs:378,381`)
  ↔ `app.js:88–103` nutzt exakt diese Form.
- `GET /api/scenarios`: `server.mjs:370–371`; feste IDs stimmen mit Contract und
  GUI-Karten überein (`lib.mjs:23–41`, `index.html:39–47`). Die GUI ruft den
  Endpunkt jedoch nie auf (Befund B4).
- `GET /architecture.json`: Contract-Form `{ok,graph:{nodes,edges}}` —
  `public/architecture.json:1–97` erfüllt sie; `app.js:105–110` liest `data.graph`.
- Bannerwerte der Contract-Liste = `BANNER`-Map (`lib.mjs:72–78`), log-Cap 200
  (`lib.mjs:226`).
- **Abweichung**: Feld `log[].t` — Contract sagt Zeitstempel ( `"t": 0` im
  Beispiel, „Log chronologisch“), Implementierung sendet Array-Index
  (`lib.mjs:226` `t: i`) → Befund B1.

### Kriterium 5 — Start · PASS mit Befund B3

- `start.sh` prüft Abhängigkeiten: Node ≥ 18 (`start.sh:10–17`), Docker
  (`start.sh:18–21`), baut einmalig nur wenn `kx/dist/*` fehlt
  (`start.sh:23–29` → `kx/scripts/build.sh`, existiert, atomarer Austausch
  Zeilen 27–31), erzeugt Server-Schlüssel einmalig (`start.sh:31–38`;
  `kx/crates/kx-core/examples/gen_server_key.rs` existiert), aktualisierts den
  Architektur-Graph (`start.sh:41`) und startet den Orchestrator via
  `exec node orchestrator/server.mjs` (`start.sh:44`).
- Makefile-Targets gegen echte Pfade: `start`→`./start.sh` (existiert, ausführbar),
  `setup`→`./lab/setup.sh` (existiert, ausführbar), `test`→
  `node --test orchestrator/*.test.mjs` (Datei existiert) + `cd kx && cargo test`,
  `graph`→`node scripts/review-graph.mjs` (existiert), `clean-lab`→
  `docker rm -f …` — **vergisst `kx-lab-c2`** (Befund B3).
- `package.json`-Scripts: `start`/`setup`/`test`/`graph` zeigen auf dieselben
  existierenden Pfade; konsistent mit Makefile.

### Kriterium 6 — Labor-Sicherheit · PASS mit Hinweisen H1, H2

- **Agent läuft nur im Container**: einziger Startpfad ist `docker run … kx-lab-patient0`
  mit Read-only-Mounts (`server.mjs:245–262`); Entrypoint führt nur
  `/opt/kx/kx-agent` aus (`lab/patient0-entrypoint.sh:7`). Kein Host-Start des
  Agenten im gesamten Orchestrator.
- **Isoliertes Netz**: `lab/setup.sh:8` `SUBNET=172.31.99.0/24`; live bestätigt:
  `docker network inspect kx-lab` → `172.31.99.0/24`; Agent/C2/Targets fest auf
  172.31.99.10/.2/.11/.12 verdrahtet (`lib.mjs:18–20`, `server.mjs:36`).
- **Wegwerf-Credentials**: `lab/Dockerfile.patient0:11–15` — frisches
  Demo-SSH-Schlüsselpaar (`kx-lab-demo-wegwerf`), AWS-RFC-Beispielwerte
  (`AKIAIOSFODNN7EXAMPLE`), Container-Passwort `patient0-lab-only`; target1
  root:root, target2 pro Lauf zufälliges Passwort (`server.mjs:193`).
- **Keine Host-Secrets**: gemountet werden nur Binaries, Assets, `server.pem`
  (öffentliches Zertifikat) und `server-pub.json` (öffentlicher Schlüssel)
  (`server.mjs:249–254`); der Private Key `lab/run/server-key.json` bleibt auf
  dem Host und wird **nicht** in Container gegeben (Rechte: 664, Hinweis H2).
  C2-Token nur als Env in Labor-Container (`server.mjs:250,163`), Datei 600
  (`server.mjs:428–431`, `stat` bestätigt `-rw-------`).
- **Keine destruktiven Payloads/Ransomware/Trojaner**: Grep über
  `kx/crates/kx-{agent,exploit,posix,core}/src` nach `rm -rf|mkfs|dd if=|shred|wiper|
  ransom|trojan|format|halt|reboot` u. ä. → keine Fundstellen außerhalb von
  Test-Aufräumcode (`persist.rs:499 remove_dir_all` nur in `#[cfg(test)]`).
  `payload.rs` = Stage1-Implant-Upload (nicht destruktiv), `persist.rs` =
  systemd-oneshot + Timer/Cron (`@reboot`), `kxenc.rs` = AEAD-Versiegelung der
  **Beute** Richtung C2 (Schlüsselweg über Server-Key), kein Verschlüsseln von
  Zielfestplatten; SETUP_LOG hält fest, dass Ransomware/Trojaner bewusst
  abgelehnt wurden (`SETUP_LOG.md` Abschnitt „Bewusst nicht gebaut“).
  `target-entrypoint.sh` setzt nur sshd-Config im Zielcontainer.
- Reset/Shutdown räumen Container: `server.mjs:341–345` (reset),
  `server.mjs:461–467` (SIGINT/SIGTERM entfernen alle vier Labor-Container).
- **Hinweis H1**: `docker network create kx-lab --subnet …` ohne `--internal`
  (`lab/setup.sh:16`; live bestätigt: `Internal=false`) → Labor-Container haben
  per Docker-NAT grundsätzlich Egress-Weg nach außen; die Isolation stützt sich
  auf die Host-Firewall (ufw). Im Code des Agenten gibt es keine Ziele außerhalb
  der fest übergebenen `--hosts`, Restrisiko bleibt aber dokumentationswürdig.

### Kriterium 7 — Doku · PASS (Befund B2; E2E-Behauptung siehe U1)

- `DEMO_SCRIPT.md:4–6` behauptet explizit echten Betrieb („Kein Fake, keine
  Simulation“); alle beschriebenen Abläufe sind im Code gedeckt: Start/Reset/
  Szenarien (`server.mjs:306–363`), Pause = `docker pause` cgroup-Freezer
  (`server.mjs:313–318`), Einzelschritt = 700 ms + Freeze (`server.mjs:321–331`),
  Architektur-Tab (`app.js:505–516`), Fehlerbanner (`app.js:57–78`), Shortcuts
  (`app.js:524–541`).
- SETUP_LOG-Stichproben:
  - „sshpass `-d 0`“ → **bestätigt**: `kx/crates/kx-exploit/src/credential_stuff.rs:166–167`
    (`cmd.args(["-d", "0", "ssh", …])`), Kommentar Zeile 129 (stdin-Lesen),
    Timeout-`continue` statt Abbruch im selben Block sichtbar.
  - „C2 als Container `kx-lab-c2`“ → **bestätigt**: `server.mjs:146–152`
    (`docker run -d --name kx-lab-c2 --network kx-lab --ip 172.31.99.2`);
    live: `docker ps` zeigt `kx-lab-c2` Up im Netz `kx-lab`.
  - „9 Crates / Architektur 9 Knoten 11 Kanten“ → **bestätigt**: `ls kx/crates`
    zählt 9; `architecture.json` und Live-GET liefern 9/11 (Detail 9).
  - „Host armserver, Docker-Netz, glibc 2.39 auf ubuntu:24.04“ → plausibel:
    Runtime arm64/Linux; `Dockerfile.patient0:5` `FROM ubuntu:24.04`.
  - E2E_PASS (22 Beute, 8.8 s usw.): **nicht erneut ausgeführt** (POST verboten),
    indirect gestützt: `orchestrator/e2e.mjs` existiert und prüft genau diese
    Zustände; `lab/run/kx.db`-Mtime 01:24 passt zur behaupteten Laufzeit → U1.
- **Befund B2**: `docs/API_CONTRACT.md:79–80` („Sandbox-Grenze“) beschreibt
  unverändert den alten Simulationsmodus („Alle Simulationen laufen in-memory
  auf virtuellen Knoten… Keine Netzwerk-Calls außer localhost“) — widerspricht
  dem echten Laborbetrieb und wäre bei der Präsentation falsch zitiert.

### Kriterium 8 — Tests ausgeführt · PASS

Kommandos und Originalausgabe (2026-11-25, 01:2x GMT+1, Verzeichnis
`/Volumes/T7/Projekte/testwurm`):

```text
$ node --check public/app.js orchestrator/server.mjs orchestrator/lib.mjs scripts/review-graph.mjs
CHECK_OK            (alle vier Dateien: keine Syntaxfehler)

$ node --test orchestrator/*.test.mjs
…
1..7
# tests 7
# suites 0
# pass 7
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 442.98
```

7/7 Tests grün (Szenarien-IDs, Log-Parsing inkl. ANSI-Strip, Zustandsableitung,
Kontext-Kompression, Grid-Koordinaten). `cargo test` (Makefile `test`) wurde
nicht ausgeführt (Rust-Build außerhalb des Review-Budgets; SETUP_LOG berichtet
21/21 Exploit-Tests).

### Kriterium 9 — Live-Zustand · PASS

```text
$ curl -s http://127.0.0.1:8321/api/state | …
ok true  runStatus "ready"  banner "Bereit"
state-Felder vollständig (nodes 9, edges 10 im Simulationsgraph, context,
telemetry, log mit 3 Einträgen, totalStepsPlanned 9)

$ curl -s -o … http://127.0.0.1:8321/architecture.json → HTTP 200
nodes 9 edges 11

$ curl -s http://127.0.0.1:8321/api/scenarios → HTTP 200, ok:true,
3 Szenarien mit IDs happy-path / error-recovery / full-traversal

$ curl -s -o /dev/null http://127.0.0.1:8321/ → HTTP 200 text/html; charset=utf-8
```

Labor live: `docker ps` → `kx-lab-c2`, `kx-lab-target1`, `kx-lab-target2` Up im
Netz `kx-lab` (Subnetz 172.31.99.0/24). Kein patient0-Container im Ready-Zustand —
Konsistent mit Reset/Ready.

---

## Befunde

| ID | Schwere | Datei:Zeile | Befund | Konkrete Reparatur |
|---|---|---|---|---|
| B1 | mittel (optisch) | `orchestrator/lib.mjs:226`, Wirkort `public/app.js:196,228–231` | Log-Einträge bekommen `t: i` (Array-Index 0…199) statt eines Zeitstempels; die GUI formatiert daraus mit `new Date(5)` → **jede Logzeile zeigt ca. „01:00:00“**, egal wann sie lief. Widerspricht dem Contract (`"t": 0` als Zeitstempel). | Beim Loggen Zeitstempel setzen (`logEvent`/`onLine` schreiben `t: Date.now()`) und in `deriveState` `e.t` statt `i` durchreichen; Contract-Beispiel ggf. präzisieren. |
| B2 | mittel (Doku) | `docs/API_CONTRACT.md:79–80` | Abschnitt „Sandbox-Grenze“ beschreibt noch die **alte In-Memory-Simulation** („läuft in-memory… keine Netzwerk-Calls außer localhost“). Die Demo fährt aber echte Docker-Container mit TLS zum C2. Falsche Sicherheitsaussage im verbindlichen Dokument. | Abschnitt auf reale Grenzen umschreiben: isoliertes Docker-Netz 172.31.99.0/24, Agent nur im Container, keine Host-Secrets, Reset räumt auf. |
| B3 | leicht | `Makefile:17–18` | `clean-lab` entfernt `kx-lab-patient0/target1/target2`, **aber nicht `kx-lab-c2`** — nach dem Ziel bleibt ein C2-Container mit Token/Datenbankfunden laufen, obwohl der Helpertext „Labor-Container entfernen“ sagt. | `docker rm -f kx-lab-c2` ergänzen (oder Helpertext anpassen). |
| B4 | leicht | `public/app.js` (kein Aufruf von `/api/scenarios`) | GUI渲染 die drei Szenario-Karten hart aus `index.html` und nutzt den Contract-Endpunkt `GET /api/scenarios` nie. Funktioniert heute, da IDs fest sind; Karten und Backend können bei Änderungen auseinanderlaufen. | Optional: Karten beim Init aus `/api/scenarios` bauen oder Contract-Text ergänzen, dass Karten statisch sein dürfen. |
| H1 | Hinweis (Sicherheit) | `lab/setup.sh:14–17` (live: `docker network inspect kx-lab` → `Internal=false`) | Labor-Netz ist nicht `--internal` angelegt; ohne die erwähnte ufw-Regel hätten Container Egress (Docker-NAT). Der Agent-Code kennt nur feste Ziel-IPs, aber die Doku („isoliert“) nennt die Firewall als tragende Säule, ohne sie im Setup zu erzwingen/checken. | `docker network create --internal` (dann C2-Ports logisch prüfen) oder in `lab/setup.sh`/SETUP_LOG die ufw-Annahme explizit verifizieren (`ufw status`-Check mit Fehlerausgabe). |
| H2 | Hinweis (Hygiene) | `lab/run/server-key.json` (Rechte 664) | Der Server-**Private**-Key liegt world-/group-readable im Run-Verzeichnis (wird nicht in Container gemountet, daher kein Leak in die Demo, aber unnötig offen). | `chmod 600 lab/run/server-key.json` (analog `token.txt`, das korrekt 600 hat) und in `start.sh:36` nach dem Erzeugen setzen. |

## Unsicherheiten

- **U1 — E2E-Claim nicht revidiert**: SETUP_LOG meldet `E2E_PASS` (22 Beute
  übertragen, 8.8/20.9 s). Da POST-Requests verboten waren, wurde `e2e.mjs`
  nicht erneut ausgeführt. Indizien: Skript vorhanden und prüft genau diese
  Kriterien; `lab/run/kx.db` (01:24) und `server.log` passen zeitlich;
  Ziel-/C2-Container laufen im Ready-Zustand. Restunsicherheit: aktueller
  E2E-Ausgang nach letzten Dateiänderungen (server.mjs 01:18) unbelegt.
- **U2 — Kein visueller Browser-Check**: Größen/Abstände wurden aus CSS-Tokens
  abgeleitet (32px/18px/64px), nicht per Screenshot/DevTools gemessen. Rendering
  (Animationen, Puls, Legende) gilt als korrekt, solange kein Browser-Fehler
  auftritt; Syntaxchecks schließen das weitgehend aus, beweisen es nicht.
- **U3 — ufw-Regel nicht verifiziert**: Die Behauptung „Host-Firewall blockiert
  Container→Host“ (`server.mjs:9–11`, SETUP_LOG) wurde nicht gegen
  `ufw status` geprüft (Host-Konfiguration außerhalb des Review-Auftrags);
  gemeinsam mit H1 Restrisiko-Bewertung offen.
- **U4 — Rust-Seite nicht gebaut/getestet**: `cargo build`/`cargo test`
  (Setup-Log: „21/21 grün“, „1 Warnung“) nicht wiederholt; `kx/dist/*`-Binaries
  existieren (01:10/01:22) und werden vom laufenden Orchestrator verwendet.
- **U5 — `scripts/review-graph.mjs` nur geprüft, nicht ausgeführt**:
  `node --check` ok; die Ausgabe wird nicht neu geschrieben, da das den
  Arbeitsbereich verändert hätte (Auftrag: keine anderen Dateien ändern).
  Eingabe (`architecture.json` committed) stimmt mit Contract überein.

## Konvention / Randnotiz

- Die GUI pollt `/api/state` mit 400 ms (Contract) ✓; Orchestrator pollt den C2
  mit 500 ms (`server.mjs:444`) — Contract-relevant nur für die GUI, in Ordnung.
- `lib.mjs`/`server.mjs` tragen `// @ts-check` und deutsche Kommentare;
  Qualität der Testabdeckung der reinen Logik angemessen (7 Unit-Tests).
