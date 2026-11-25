# Addon-Verfügbarkeit – testwurm (Briefing)

Recherche: 2026-11-25 · Researcher-Session a8e5ed97 · Methoden: lokale Skill-Verzeichnisse (ls/grep), `skills_search` (5 Queries), npm-Registry (8 Aufrufe), web_search (3 Queries).
Geprüfte lokale Quellen: `~/.agents/skills/` (151 Skills), `~/.openclaw/plugin-skills/`, `~/.openclaw/agents/coordinator/agent/workshop-skills/` (5 eigene Skills, keine Treffer), `~/.nvm/versions/node/v26.13.1/lib/node_modules/openclaw/skills/`.

---

## 1. GSD Skills (Get Shit Done / Workflow-Skills)

**Status: NICHT VERFÜGBAR → FALLBACK**

Evidenz:
- Lokal: Kein Skill mit `gsd`/`get-shit-done` in einem der vier Verzeichnisse (ls/grep, case-insensitive). `skills_search` ("get shit done workflow") liefert nur `n8n-workflow-patterns`, `cli-builder` u. ä.
- npm: `gsd-skills` → 404 (2026-11-25).
- Web: Das System existiert tatsächlich als öffentliches GitHub-Projekt: `github.com/gsd-build/get-shit-done` ("meta-prompting, context engineering and spec-driven development system for Claude Code by TÂCHES"; gefunden via web_search, nicht direkt verifiziert — ⚠️ third-party-Listings mit Sternen-Zahlen = unsicher). Es ist aber **nicht installiert** und kein npm-Paket.

Fallback (lokal, offline-fähig):
- Workflow-Ketten aus installierten Skills nachbauen: `brainstorming` → `prd-generator` → `tad-generator` → `tasks-generator` → `executing-plans` (alle in `~/.agents/skills/`). Das deckt den GSD-Kern (Spec → Tasks → Ausführung) als eigene, dokumentierte Pipeline ab — ideal für die Demo, da keine Netzwerk-Abhängigkeit.

## 2. Matt Pocock Skills (TypeScript-/Engineering-Skills)

**Status: ÄQUIVALENT GEFUNDEN**

Evidenz:
- Lokal: Kein Skill mit `pocock`/`effect-smol` im Namen. Aber TS-Engineering-Abdeckung vorhanden: `skill-code` ("Implementierung, Bugfixing, Refactoring, TypeScript/React/Next.js…"), `senior-frontend`, `senior-backend`, `senior-fullstack`, `test-coverage`, `slop-cleanup` (alle `~/.agents/skills/`).
- npm: `@mattpocock/skills` → 404; `effect-smol` → 404.
- Web: `github.com/mattpocock/skills` existiert ("Skills for Real Engineers. Straight from my .agents directory", u. a. `/tdd`-Skill; Quellen: GitHub, aihero.dev, skills.rest — ⚠️ Suchmaschinen-Snippets, nicht alle Details verifiziert). Nicht installiert.

Fallback/Empfehlung:
- Für die Demo die installierten Äquivalente nutzen (`skill-code`, `senior-frontend`, `test-coverage`); TS-Pattern-Wissen ist damit abgedeckt. Wer die Pocock-Skills will, müsste `github.com/mattpocock/skills` klonen (einmalig Netz, danach offline lauffähig) — optional, nicht nötig.

## 3. code-review-graph (Abhängigkeits-/Review-Graph)

**Status: ÄQUIVALENT GEFUNDEN (Review-Teil), Graph-Teil NICHT VERFÜGBAR → FALLBACK**

Evidenz:
- Lokal: Kein Skill/MCP namens `code-review-graph` installiert. Einziger Fund: Der installierte Skill `clawpatch-expert` **erwähnt** `code-review-graph` MCP-Tools nur als Fremdkonzept ("Strukturelle Graph-Queries → code-review-graph MCP-Tools (siehe Agora-CLAUDE.md)", SKILL.md Zeile 65) — ein MCP-Server dazu ist in `~/.openclaw/*.json` nicht konfiguriert.
- npm: `code-review-graph` → 404. Web: Existiert als MCP-Server/Ökosystem (mcpmarket.com, glama.ai, PyPI `better-code-review-graph`; Tree-sitter-AST + GraphRAG) — ⚠️ nur Suchtreffer, nicht verifiziert; nicht installiert. Kein `madge` im PATH.
- Installierte Review-Äquivalente: `code-review`, `code-reviewer`, `frontend-code-review`, `receiving-code-review`, `requesting-code-review`, `test-coverage` (alle `~/.agents/skills/`).

Fallback (lokal):
- Review: `code-review`/`code-reviewer`-Skills direkt verwenden.
- Graph: zur Bauzeit generieren statt Laufzeit-MCP — `madge`/`tsc`-Imports oder ein kleines Python-/Node-Skript, das `import`/`require`-Kanten parsed und DOT/Mermaid ausgibt; Ergebnis als statischer Graph in die Repo-Doku. Passt zum "lokal, ohne Netz zur Laufzeit"-Ziel.

## 4. contextmode / context-mode (Kontext-Kompression)

**Status: ÄQUIVALENT GEFUNDEN**

Evidenz:
- npm: **`context-mode` v2.2.3 existiert** — "Context window saver for 11 coding agents. Local and free: sandboxed code execution, FTS5 search, session continuity." (npm view, 2026-11-25). Exaktes `contextmode` → 404 (maßgeblich ist der Bindestrich-Name).
- Lokal: Kein Kontext-Kompressions-Skill installiert. Nächste Äquivalente: `memory-hygiene` (Vektor-Memory-/Token-Optimierung, `~/.agents/skills/`), plus OpenClaw-eingebaute Mechanik (Skill-Truncation, subagent yields, compact session snapshots).

Fallback/Empfehlung:
- Für die Demo: eigene, sichtbare Kontext-Kompression zeigen — Summaries/Handoff-Verträge + `memory-hygiene`-Muster; `context-mode` (npm) wäre nur eine optionale Installation mit Netz beim Setup. Kein Zwang.

## 5. Figma Addon / Integration (Plugin, Design-Token-Sync, MCP „figma")

**Status: ÄQUIVALENT GEFUNDEN**

Evidenz:
- Lokal: Kein Figma-Skill, keine Figma-MCP-Konfiguration (grep über `~/.agents/skills`, `~/.openclaw/plugin-skills`, OpenClaw-Skills, `~/.openclaw/*.json` → 0 Treffer außer irrelevanten).
- npm: `@figma/plugin-typings` v1.143.0 existiert (Plugin-API-Typen); `figma-mcp` v0.1.4 existiert (MCP-Server für Figma, alt/klein ⚠️).
- Installierte Design-Äquivalente (Stitch-Suite + mehr, `~/.agents/skills/`): `stitch-generate-design` (explizit "design tokens and theme system"), `stitch-extract-design-md` ("extract design tokens from source files"), `stitch-manage-design-system`, `design-md`, `taste-design`, `frontend-design`.

Fallback (lokal):
- Design-Token-Sync ohne Figma-Calls: Tokens als `tokens.json` (W3C-Design-Token-Format, figma-inspiriert) + generiertes CSS-Variablen-File im Repo pflegen; `stitch-extract-design-md`/`design-md` für die Docs. Live-Figma braucht API-Token + Netz → bewusst NICHT für die Laufzeit-Demo.

---

## Summary-Tabelle

| # | Komponente | Status | Kern-Evidenz | Empfohlener Fallback (offline-fähig) |
|---|------------|--------|--------------|--------------------------------------|
| 1 | GSD Skills | NICHT VERFÜGBAR → FALLBACK | lokal 0 Treffer; npm 404; nur GitHub-Projekt gsd-build/get-shit-done (Suchtreffer ⚠️) | Pipeline aus `brainstorming`→`prd-generator`→`tasks-generator`→`executing-plans` |
| 2 | Matt Pocock Skills | ÄQUIVALENT GEFUNDEN | npm 404; Repo mattpocock/skills existiert (⚠️); lokal `skill-code`, `senior-*`, `test-coverage` | Installierte TS-Skills nutzen; Pocock-Repo optional klonen |
| 3 | code-review-graph | ÄQUIVALENT (Review) / FALLBACK (Graph) | npm 404; nur in clawpatch-expert erwähnt, MCP nicht konfiguriert; lokal `code-review`/`code-reviewer` | Review-Skills + bauzeitlicher Import-Graph (madge/Skript → DOT/Mermaid) |
| 4 | contextmode / context-mode | ÄQUIVALENT GEFUNDEN | npm `context-mode@2.2.3` real; lokal kein Install-Treffer; `memory-hygiene` vorhanden | Eigene Kontext-Kompression (Summaries + `memory-hygiene`-Muster) |
| 5 | Figma Addon/Integration | ÄQUIVALENT GEFUNDEN | npm `@figma/plugin-typings@1.143.0`, `figma-mcp@0.1.4`; lokal 0 Figma-Treffer; Stitch-Suite installiert | Figma-inspirierte Design-Tokens als JSON/CSS + `design-md`/`stitch-*` |

## Gesamtempfehlung für den Bau

Alle 5 Komponenten sind in der Demo **ohne externe Installationen und ohne Netz zur Laufzeit** simulierbar:
1. **Workflow (GSD-Ersatz):** installierte Generator-/Planner-Skills als dokumentierte Kette verdrahten.
2. **TS-Engineering (Pocock-Ersatz):** `skill-code` + `senior-frontend`/`senior-backend` + `test-coverage`.
3. **Review-Graph:** `code-review`/`code-reviewer`-Skills + generierter statischer Dependency-Graph als Artefakt.
4. **Context-Mode:** eigene Kompressions-Logik (Session-Summary/Handoff-Format), inspiriert vom npm-`context-mode`-Pitch.
5. **Figma:** `tokens.json` + CSS-Variablen + `design-md`-Output statt Live-Figma.

**Unsicherheiten (explizit):** Web-Befunde (#1–#3, #5) stammen aus Suchmaschinen-Snippets externer Seiten und wurden nicht direkt auf GitHub/npm verifiziert; npm-Versionen sind Momentaufnahme 2026-11-25. Ob `figma-mcp`/`context-mode` funktional überzeugen, ist ungetestet — für die Demo aber irrelevant, da Fallbacks ohne sie auskommen.
