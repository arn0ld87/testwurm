# SETUP_LOG · Testwurm-Präsentationsaufbau

Stand: 2026-11-25 · Projekt: `/Volumes/T7/Projekte/testwurm`
Basis: echtes kx-Repo (github.com/arn0ld87/testwurm, HEAD `a483d2d`), Rust-Workspace mit 9 Crates.

## Umgebung

- Host: armserver, Linux arm64, Node v22.22.1, Docker vorhanden, Rust/Cargo vorhanden.
- `/Volumes/T7` ist ein lokales Verzeichnis (kein Mac-Node); Schreibrechte per `chown alex:alex` eingerichtet.
- npm-Registry erreichbar; keine CDNs/externen Assets in der GUI.

## Was gebaut wurde

| Komponente | Pfad | Zweck |
|---|---|---|
| GUI (Vanilla HTML/CSS/JS) | `public/` | Deutsche Oberfläche: Live-Graph, Szenarien, Log, Kontext-Panel, Architektur-Tab |
| Design-Tokens (Figma-Äquivalent) | `docs/figma-tokens.json` | Farben/Abstände/Schatten als JSON, in `styles.css` umgesetzt |
| API-Vertrag | `docs/API_CONTRACT.md` | GUI ↔ Orchestrator |
| Orchestrator-Logik | `orchestrator/lib.mjs` | Szenarien, Zustandsableitung aus echten C2-Daten, Log-Parsing, Kontext-Kompression |
| Orchestrator-Server | `orchestrator/server.mjs` | Steuert echten kx-Server + Agent im Docker-Labor, bedient GUI-API |
| Tests | `orchestrator/lib.test.mjs` | `node --test orchestrator/*.test.mjs` |
| Labor | `lab/` | Docker-Netz `kx-lab` (172.31.99.0/24), Ziel- und Patient-Images, idempotentes `setup.sh` |
| Architektur-Graph | `scripts/review-graph.mjs` | Cargo-Manifeste → `public/architecture.json` (9 Knoten, 11 Kanten) |
| Start | `start.sh`, `Makefile`, `package.json` | Ein Befehl: `./start.sh` |
| Demo-Plan | `DEMO_SCRIPT.md` | 60–90s-Präsentationsablauf |

## Labor-Architektur (echt, keine Simulation)

```
Host (armserver)
├── GUI-Orchestrator → http://127.0.0.1:8321
└── Docker-Netz kx-lab (172.31.99.0/24, isoliert)
    ├── kx-lab-c2        172.31.99.2   → echter kx-server (TLS, CN kx-c2.lab, Bearer-Token)
    ├── kx-lab-patient0  172.31.99.10  → echter kx-agent (ubuntu:24.04, glibc-kompatibel)
    ├── kx-lab-target1   172.31.99.11  → SSH, root:root (Default-Credentials)
    └── kx-lab-target2   172.31.99.12  → SSH, zufälliges starkes Passwort
```

- C2 als Container, weil die Host-Firewall (ufw) Container→Host-Verbindungen blockiert; Container→Container im Labor-Netz ist frei.

- Agent läuft **nur** im Container; Beute (Shadow, SSH-Key, AWS-Beispielwerte) sind Wegwerf-Daten im Container.
- Persistenz (systemd) schlägt im Container fehl → wird als Warnung ehrlich angezeigt (gelber Knoten).
- Pause = `docker pause` (cgroup-Freezer), Einzelschritt = 700 ms Lauf + Freeze.
- Reset entfernt Agent-Container, löscht die C2-DB, baut Ziele frisch.
- Beute-Versiegelung: `gen_server_key` (hybrid) erzeugt `lab/run/server-key.json` + `server-pub.json`.

## Addon-Integration (ehrlicher Status)

1. **GSD Skills** – npm-Paket existiert nicht (404). **Echtes Repo geklont:** `gsd-build/get-shit-done` → `~/.agents/skills/vendor/get-shit-done` (komplettes Framework: commands/, agents/, sdk/, skills/gsd). Referenzmaterial für die Workflow-Pipeline; kein npm-Install nötig.
2. **Matt Pocock Skills** – npm-Paket existiert nicht (404). **Echtes Repo geklont:** `mattpocock/skills` → `~/.agents/skills/vendor/mattpocock-skills` (39 SKILL.md-Dateien in engineering/, productivity/, misc/).
3. **code-review-graph** – npm 404; PyPI-Treffer nur Rename-Stub. **Installiert: echte CLI aus `tirth8205/code-review-graph`** (`~/.local/bin/code-review-graph`). **Benutzt (2026-11-25 01:29):** voller Graph-Build über den Workspace (82 Dateien, 976 Knoten, 10133 Kanten, 10 Communities); `impact` auf die Bugfix-Datei `credential_stuff.rs` (16 geänderte Knoten, 2 im Umkreis von 2 Hops betroffen, Risiko „low“); HTML-Visualisierung. Exporte: `lab/run/crg/architecture.json`, `lab/run/crg/impact-credential-stuff.json`, `lab/run/crg/graph.html`. Auffrischen: `make crg`. **Semantische Suche aktiv (2026-11-25 01:38):** Embeddings-Extra installiert (`sentence-transformers`, lokales `all-MiniLM-L6-v2`, keine Cloud-Keys), 894 Knoten eingebettet; verifiziert mit deutschen Natural-Language-Queries im Hybrid-Modus: „passwörter raten und ssh login“ → `sshpass_befehl`/`extract_ssh_keys`, „beute extrahieren und zum server schicken“ → `melde_beute`. Die GUI-Architekturansicht speist unabhängig davon der Cargo-Manifest-Graph (`scripts/review-graph.mjs`, 9 Knoten/11 Kanten) – crg ist Analyse-Werkzeug, keine Laufzeit-Abhängigkeit.
4. **contextmode** – heißt `context-mode` (npm v2.2.3), installiert nach `~/.npm-global`. **Benutzt (2026-11-25 01:29):** Projekt neu indexiert mit `context-mode index . --max-files 400 --ext .mjs,.js,.md,.rs,.html,.css,.sh,.toml` → **186 Dateien, 1403 Sections** (FTS5); Suche verifiziert (`context-mode search "sshpass"` liefert README- und Issue-Treffer). Vorheriger Index war leer/veraltet – deshalb hier die echte Neu-Indexierung. Das Kompressions-Prinzip (Summaries + Tail statt Voll-Log) ist zusätzlich im Orchestrator umgesetzt; `savedPct` wird **echt berechnet** (Zeichen/4-Schätzung), nicht behauptet.
5. **Figma** – kein MCP konfiguriert; Äquivalent: Design-Tokens als JSON + CSS-Variablen.

## Verifikation

- **Reviewer-Abnahme (2026-11-25 01:34, `review/abnahme.md`): BESTANDEN, alle 9 Kriterien PASS**, 4 leichte Befunde + 2 Sicherheitshinweise. Alle anschließend behoben:
  - B1: Log-Zeitstempel waren Array-Indizes → jetzt echte Epoch-ms (`server.mjs` beim Loggen, `lib.mjs` reicht `e.t` durch); live verifiziert.
  - B2: `docs/API_CONTRACT.md` „Sandbox-Grenze“ beschrieb noch die alte Simulation → auf reales Labor umgeschrieben.
  - B3: `make clean-lab` vergaß `kx-lab-c2` → ergänzt.
  - B4: GUI-Karten werden jetzt beim Init aus `GET /api/scenarios` synchronisiert (statische Karten als Fallback).
  - H1: Labor-Netz jetzt mit `--internal` (live: `Internal=true`, kein Egress); `lab/setup.sh` entsprechend geändert.
  - H2: `lab/run/server-key.json` Rechte 600 (live gesetzt + in `start.sh` nach Erzeugung).
- **E2E-Test erneut bestanden (2026-11-25 01:45, nach allen Fixes, auf `--internal`-Netz): `E2E_PASS`** – alle drei Szenarien mit echtem Wurm:
  - Happy Path: target1 kompromittiert (root:root), 22 Beute übertragen, 0 verloren, Laufzeit 8.8 s.
  - Fehler & Recovery: target2 erkannt aber kein Zugriff (warning), Operator-Task ausgeführt (done), 20.9 s.
  - Full Traversal: beide Ziele, gemischte Ergebnisse, Task-Kanal grün.
  - Reset → Bereit, Architektur-Graph 9/11, GUI-HTML korrekt.
- Persistenz-Knoten bewusst gelb: kein systemd im Container, Fehler wird abgefangen (ehrliche Anzeige).
- `node --check` für alle JS-Dateien: OK.
- `node --test orchestrator/*.test.mjs`: 7 Tests (Szenarien, Log-Parsing, Zustandsableitung, Kompression, Grid).
- `cargo build --workspace`: erfolgreich (1 Warnung: unbenutzter Import in `kx-core/format.rs`, Bestand).
- GUI-Contract geprüft: `/api/state`, `/api/scenarios`, `/api/control`, `/architecture.json`; keine externen URLs.
- C2-Routen/Argumente gegen den Rust-Quellcode verifiziert (`kx-core/src/c2.rs`, `kx-server/src/main.rs`, `kx-agent/src/main.rs`).
- Task-Anlage erst nach Agent-Registrierung (C2 lehnt Tasks für unbekannte Hosts ab).
- glibc-Falle behoben: patient0 auf `ubuntu:24.04` (Binary braucht GLIBC_2.39, bookworm hätte 2.36).
- Firewall-Falle behoben: ufw blockiert Container→Host; der C2-Server läuft deshalb selbst als Container `kx-lab-c2` (172.31.99.2) im Labor-Netz. Agent→C2-Verbindung verifiziert (TCP-Check aus patient0-Image).
- ANSI-Escape-Codes im Agent-Log werden vor dem Parsing entfernt.
- **Zwei echte Bugs im kx-Code lokal behoben** (nicht gepusht):
  1. `kx-exploit/src/credential_stuff.rs`: `sshpass -f -` öffnet eine Datei namens `-` statt stdin zu lesen → jeder Versuch lief ins 10s-Timeout. Fix: `sshpass -d 0` (Deskriptor 0). Manuell verifiziert: Root-Login in 0.39 s.
  2. Ebenda: Ein Timeout brach die gesamte Credential-Schleife ab (`return Err`), sodass funktionierende Default-Credentials nie probiert wurden. Fix: `continue` zur nächsten Kombination; Test angepasst. 21/21 Exploit-Tests grün.
- `kx/scripts/build.sh`: Binary-Austausch jetzt atomar (tmp + mv), sonst scheitert der Rebuild an gemounteten, laufenden Binaries ("Text file busy").

## Bewusst nicht gebaut

- **Ransomware/Trojaner** – abgelehnt (destruktive Payloads, auch im Labor). Angebotene Alternative: EICAR-Testdatei für eine AV-Detection-Demo (keine Zusage erfolgt).

## Bekannte Grenzen

- Der Agent ist ein Einmal-Lauf (kein Daemon); „Pause" friert den Container ein, statt einen Loop anzuhalten.
- `savedPct` ist eine Zeichenschätzung (÷4), keine Tokenizer-Messung.
- SMB-Relay-Pfad wird im Labor nicht ausgelöst (keine Windows-Ziele); nur SSH-Default-Credentials sind demonstrierbar.