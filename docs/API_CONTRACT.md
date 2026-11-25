# Testwurm API-Contract (verbindlich für GUI und Engine)

Server: Node.js built-in `http`, Port 8321 (Fallback 8322–8330). Alles lokal, keine externen Dienste.
Die GUI pollt `GET /api/state` alle 400 ms (kein SSE nötig). Jede Antwort ist JSON.

## Endpunkte

### GET /api/state
Antwort-Envelope:
```json
{ "ok": true, "state": { ... } }
```
`state`-Form (alle Felder immer vorhanden):
```json
{
  "runStatus": "ready | running | paused | completed | error_contained",
  "scenarioId": "happy-path",
  "scenarioName": "Happy Path",
  "seed": 1337,
  "tick": 0,
  "totalStepsPlanned": 12,
  "worm": {
    "currentNodeId": "n0",
    "path": ["n0"],
    "status": "idle | moving | checking | recovering"
  },
  "nodes": [
    {
      "id": "n0",
      "label": "Eingang",
      "kind": "module | test | target",
      "status": "pending | active | passed | warning | failed | recovered | skipped",
      "x": 0, "y": 1,
      "checks": 0,
      "detail": "Kurzerklärung des Knotens"
    }
  ],
  "edges": [ { "from": "n0", "to": "n1" } ],
  "log": [
    { "t": 0, "level": "info | warn | error | success", "msg": "Kurztext (≤120 Zeichen)", "detail": "optionaler Langtext, standardmäßig eingeklappt" }
  ],
  "context": { "rawTokens": 0, "keptTokens": 0, "savedPct": 0, "summaries": 0 },
  "telemetry": { "nodesVisited": 0, "checksRun": 0, "errorsCaught": 0, "recoveries": 0, "durationMs": 0 },
  "banner": "Bereit"
}
```
- `x`,`y` sind Grid-Koordinaten (Spalte/Zeile, kleine ganze Zahlen ≥0). Die GUI mappt sie auf SVG.
- `banner` ist ein deutscher Klartext-Status: `Bereit`, `Läuft`, `Pausiert`, `Abgeschlossen`, `Fehler abgefangen`.
- `log` enthält maximal die letzten 200 Einträge, chronologisch.

### POST /api/control
Body: `{ "action": "start" | "pause" | "step" | "reset", "scenarioId": "happy-path" | "error-recovery" | "full-traversal" }`
- `scenarioId` nur bei `reset` (oder vor erstem Start) relevant; sonst optional.
- `start`: läuft automatisch (Server-Tick alle 700 ms). `pause`: hält an. `step`: genau ein Tick (auch aus `paused`/`ready`). `reset`: Ausgangszustand des (ggf. neuen) Szenarios.
- Antwort: gleiche Envelope wie `/api/state` mit dem neuen Zustand.
- Fehler: HTTP 400, `{ "ok": false, "error": "deutsche Fehlermeldung" }`.

### GET /api/scenarios
```json
{ "ok": true, "scenarios": [ { "id": "happy-path", "name": "Happy Path", "description": "…", "nodeCount": 9 } ] }
```
Feste IDs: `happy-path`, `error-recovery`, `full-traversal`.

### GET /architecture.json (statische Datei)
Modul-Abhängigkeitsgraph des Projekts (Fallback für `code-review-graph`):
```json
{ "ok": true, "graph": { "nodes": [ { "id": "engine", "label": "engine.ts", "group": "core | server | gui | scripts" } ], "edges": [ { "from": "server", "to": "engine" } ] } }
```

## GUI-Pflichten (Public-Dateien)
- Vanilla HTML/CSS/JS, **keine CDNs, keine externen Fonts, keine Build-Tools**. Dateien: `public/index.html`, `public/app.js`, `public/styles.css`.
- Sprache: Deutsch. Große Buttons: `Start`, `Pause`, `Einzelschritt`, `Reset Demo`; Szenario-Auswahl als 3 große Karten (Happy Path / Fehler & Recovery / Full Traversal).
- Status-Banner oben (Farbe je `runStatus`), SVG-Graph mittig (Knotenfarbe je `status`: pending grau, active blau+pulsierend, passed grün, warning amber, failed rot, recovered türkis, skipped hellgrau; Wurm-Pfad als hervorgehobene Kantenfolge + Marker für die aktuelle Position), rechts Kontext-Panel (`savedPct` groß, rawTokens/keptTokens/summaries) und Telemetrie-Zähler, unten Live-Log (level-Farben, `detail` per Klick aufklappbar, Autoscroll).
- Tab/Toggle „Architektur“ zeigt `/architecture.json` als zweiten SVG-Graphen.
- Fehlerresistenz: `window.onerror` + `unhandledrejection` → rotes Banner „Fehler abgefangen – Oberfläche bleibt bedienbar“, Eintrag ins Log, Polling läuft weiter. Fetch-Fehler → Banner „Verbindung zum Server verloren – Reconnect läuft“, automatischer Retry. Kein weißer Bildschirm.
- Design-Tokens als CSS-Variablen in `:root` (Figma-inspiriert), zusätzlich maschinenlesbar in `docs/figma-tokens.json`.
- Tastatur: Leertaste = Start/Pause, `S` = Einzelschritt, `R` = Reset. Keine Terminal-Kenntnisse nötig.

## Sandbox-Grenze (echtes Labor)
Die Demo fährt **echte Container** im isolierten Docker-Netz `kx-lab` (`172.31.99.0/24`, `--internal`, kein Egress). Der Agent läuft ausschließlich im Container `kx-lab-patient0`; Beute und Persistenz entstehen nur dort. Ziele sind ausschließlich die Labor-Container `kx-lab-target1`/`-target2` mit Wegwerf-Credentials. Keine Host-Secrets werden in Container gemountet; der private Server-Schlüssel bleibt auf dem Host (Rechte 600). Reset und Shutdown entfernen die Labor-Container. Keine destruktiven Payloads, keine Ransomware, keine Trojaner. Der GUI-Orchestrator selbst läuft auf dem Host und spricht nur `127.0.0.1` (GUI) bzw. die Labor-IPs (C2-Abfrage).