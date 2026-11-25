# Abschlussbericht · Testwurm-Präsentations-Demo

Stand: 2026-11-25 01:47 GMT+1 · Projekt: `/Volumes/T7/Projekte/testwurm`
Ergebnis: **Präsentationsreif.** Echter kx-Netzwerkwurm (Rust) im isolierten
Docker-Labor, idiotensichere deutsche GUI, Ein-Befehl-Start. Keine Simulation.

---

## 1. Verzeichnisstruktur & Startbefehl

```
testwurm/
├── start.sh              ← EIN Befehl für die Präsentation
├── Makefile              (start / setup / test / graph / crg / clean-lab)
├── package.json          (keine npm-Abhängigkeiten, nur Node-Built-ins)
├── public/               GUI: index.html, app.js, styles.css, architecture.json
├── orchestrator/         server.mjs, lib.mjs, Tests, e2e.mjs (Node ≥ 18)
├── lab/                  Docker-Labor: setup.sh, Dockerfiles, Entrypoints, run/
│   └── run/crg/          code-review-graph-Exporte (Architektur, Impact, HTML)
├── kx/                   echter Rust-Wurm (9 Crates), dist/ mit Release-Binaries
├── scripts/              review-graph.mjs (GUI-Architekturgraph aus Cargo-Manifesten)
├── docs/                 API_CONTRACT.md, figma-tokens.json, gui-screenshot.png
├── review/               abnahme.md (unabhängiger Reviewer-Bericht)
├── research/             addons-brief.md (Addon-Recherche mit Quellen)
├── DEMO_SCRIPT.md        60–90s-Skript mit Klicks und Sprechtext
└── SETUP_LOG.md          ehrliches Bautagebuch inkl. Bugfixes und Verifikation
```

**Start (ein Befehl):**
```bash
cd /Volumes/T7/Projekte/testwurm && ./start.sh
```
Prüft Node/Docker, baut einmalig die Rust-Binaries (falls fehlend), erzeugt
Server-Schlüssel (Rechte 600), aktualisiert den Architekturgraph, startet
GUI + Labor und öffnet den Browser auf `http://127.0.0.1:8321`.
`Strg+C` beendet alles und räumt die Labor-Container ab.

**Labor-Architektur:** Docker-Netz `kx-lab` (172.31.99.0/24, **`--internal`,
kein Egress**). C2 als Container `kx-lab-c2` (.2), Agent `kx-lab-patient0`
(.10, ubuntu:24.04 wegen GLIBC_2.39), Ziele `kx-lab-target1` (.11, root:root)
und `kx-lab-target2` (.12, starkes Passwort). GUI-Orchestrator auf dem Host.

## 2. Addon-Integration (was wirklich benutzt wird)

| Addon | Status | Echte Nutzung |
|---|---|---|
| **GSD Skills** | Repo geklont → `~/.agents/skills/vendor/get-shit-done` | Referenzmaterial für die Workflow-Pipeline (Spec → Tasks → Ausführung); npm-Paket existiert nicht (404) |
| **Matt Pocock Skills** | Repo geklont → `~/.agents/skills/vendor/mattpocock-skills` (39 Skills) | Engineering-Patterns (code-review, tdd, diagnosing-bugs) im Arbeitsprozess genutzt |
| **code-review-graph** | Echte CLI v2.4.0 installiert (`~/.local/bin`) | Voller Graph: 82 Dateien, 976 Knoten, 10133 Kanten. `impact` auf die Bugfix-Datei (16 Knoten direkt, 2 im Umkreis, Risiko low). **Semantische Suche aktiv:** 894 Embeddings (lokales all-MiniLM-L6-v2), deutsche Queries finden Funktionen („passwörter raten und ssh login" → `sshpass_befehl`). Exporte: `lab/run/crg/`, Refresh: `make crg` |
| **context-mode** | npm v2.2.3 (`~/.npm-global`) | Index: 186 Dateien, 1403 Sections (FTS5), Suche verifiziert. Kompressions-Prinzip (Summaries + Tail) im Orchestrator umgesetzt; `savedPct` echt berechnet (bis 27 % im Fehler-Szenario) |
| **Figma** | Kein Live-MCP (bewusst, offline-Ziel) | Design-Tokens `docs/figma-tokens.json` → 1:1 als CSS-Variablen; GUI per Screenshot visuell abgenommen (`docs/gui-screenshot.png`) |

## 3. Demo-Ablaufplan (60–90 s)

Vollständig mit Sprechtext in `DEMO_SCRIPT.md`. Kurzfassung:

| Zeit | Klick | Was passiert |
|---|---|---|
| 0–10 s | – | GUI zeigen: Banner „Bereit", Steuerung links, Live-Graph Mitte, Kontext-Panel rechts |
| 10–35 s | Karte „Happy Path" → **Start** | Echter Wurm: Registrierung → Beute (22 Objekte) → Scan → target1 per root:root → Beute-Meldung. Knoten werden grün; die Persistenz läuft im Container ohne systemd über den @reboot-Cron-Job (Fallback). savedPct steigt |
| 35–60 s | **Reset Demo** → „Fehler & Recovery" → **Start** | target2 mit starkem Passwort: Zugriff scheitert sauber (gelb), Operator-Task wird trotzdem ausgeführt (grün), Telemetrie zählt Fehler + Erholung |
| 60–80 s | Tab **Architektur** | 9 Crates, 11 echte Abhängigkeitskanten aus Cargo-Manifesten |
| 80–90 s | Tab **Live-Labor** → **Reset Demo** | Container weg, alles wieder „Bereit". Fazit |

Shortcuts: `Leertaste` Start/Pause · `S` Einzelschritt · `R` Reset.
Pause = echter cgroup-Freezer; Einzelschritt = 700 ms Lauf + Freeze.

## Verifikation (alles live geprüft)

- **E2E `E2E_PASS` (01:45, auf `--internal`-Netz, nach allen Fixes):** Happy Path
  completed (22 Beute, 0 verloren, 7.8 s), Fehler & Recovery completed
  (Task done, 20.9 s, savedPct 27, 1 Recovery), Full Traversal completed.
  Reset → „Bereit". Architektur 9/11. GUI-HTML OK.
- **Unit-Tests:** Orchestrator 7/7, Rust-Workspace 228 Tests grün
  (1 bekannte Warnung: unused import `KexId` in kx-core/format.rs).
- **Reviewer-Abnahme (`review/abnahme.md`):** BESTANDEN, 9/9 Kriterien PASS.
  Alle 6 Befunde/Hinweise danach behoben und Gegenprobe gefahren:
  echte Log-Zeitstempel (live verifiziert), Contract-Doku korrigiert,
  `clean-lab` inkl. C2, GUI-Karten aus `/api/scenarios`, Netz `--internal`,
  Private-Key-Rechte 600.
- **GUI visuell geprüft** (Headless-Screenshot): Figma-Tokens umgesetzt,
  Label-Overlapping gefunden und gefixt.
- **Zwei echte kx-Bugs lokal gefixt** (nicht gepusht): `sshpass -f -` → `-d 0`
  (Timeout-Falle) und Abbruch der Credential-Schleife bei Timeout → `continue`.
  21/21 Exploit-Tests grün.

## Offene Punkte / Grenzen

- **Push der kx-Bugfixes** braucht Alex' Freigabe (lokal gefixt, getestet).
- **Proxmox-Windows-Ziele:** `pve01-bfwlab` gefunden, aber kein SSH-Zugang
  mit vorhandenen Keys. Braucht Zugang/credentials von Alex; kx-Windows-Pfad
  (SMB/WinRM) wäre eigene Integrationsarbeit. Docker-Labor bleibt die
  deterministische Präsentationsbasis.
- **Bewusst nicht gebaut:** Ransomware/Trojaner (auch im Labor abgelehnt),
  destruktive Payloads. EICAR-Detection-Demo angeboten, keine Zusage.