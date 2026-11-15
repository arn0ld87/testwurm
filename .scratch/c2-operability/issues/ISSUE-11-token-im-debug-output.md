---
id: ISSUE-11
title: Args leitet Debug ab — das C2-Token landet in jeder Debug-Ausgabe
status: done
category: bug
triage_state: erledigt
agent_brief: briefs/ISSUE-11-token-aus-debug-output.md
priority: medium
---

## Description

`Args` in `kx-agent/src/main.rs` leitet `Debug` ab:

```rust
#[derive(Parser, Debug)]
struct Args { … token: String … }
```

Damit ist das Bearer-Token über jede Debug-Ausgabe der Struktur erreichbar — `{:?}` auf `Args`, ein `tracing`-Event mit `?args`, ein Panic-Backtrace mit lokalen Variablen oder ein `dbg!(args)` in einer Fehlersuche gibt das Token im Klartext aus.

Der C2-Token ist der Zugriffsschlüssel für Agent und CLI. Er steht laut `kx/crates/kx-server/src/README.md` ohnehin im Klartext auf stderr, wenn der Server keines bekommt — die Problematik ist also etabliert, aber der `Debug`-Derive macht sie zusätzlich über die *Prozess-Logs* des Agenten erreichbar, die typischerweise in Journald landen.

Verifiziert am 2026-11-11 per Quellcode-Prüfung: `kx-agent/src/main.rs` (`Args`).

Related: ISSUE-10

## Acceptance Criteria

- [x] `Args` leitet **kein** `Debug` mehr ab, oder das Token-Feld ist mit einem eigenen Typ gekapselt, dessen `Debug` den Wert maskiert (`f.debug_struct("Args").field("token", &"***").finish()`)
- [x] Der `Debug`-Derive auf `Args` wird nirgends im Crate genutzt, wo er das Token sichtbar macht
- [x] Ein Test prüft, dass eine Debug-Ausgabe der Argumente das Token nicht enthält

## Technical Notes

- Betroffen: `kx-agent/src/main.rs` (`#[derive(Parser, Debug)] struct Args`)
- Der übliche Weg ist eine Wrapper-Struktur: `struct Secret(String)` mit `impl fmt::Debug for Secret { fn fmt(...) { write!(f, "***") } }` und `impl From<String> for Secret`. Das Token bleibt dann in jedem Kontext maskiert
- `clap` selbst braucht `Debug` nicht — der Derive ist also frei entbehrlich, sofern `Args` nicht in einer Fehlermeldung formatiert wird
- Gleiches Muster prüfen: `kx-cli/src/main.rs` (`Cli`) — dort leitet die Struktur ebenfalls `Debug` ab und enthält ein Token-Feld

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der Befund ist bestätigt: Die Argumentstruktur des Agenten leitet Debug ab und
  trägt das Token als String in einem Feld. Eine Debug-Ausgabe gibt den
  Zugangsschlüssel im Klartext aus.
- Das Ausgabeverhalten ist aktuell harmlos: die Struktur wird nirgends
  debug-ausgegeben. Die Operator-CLI hat ihre Argumentstruktur ohne
  Debug-Ableitung — das ist der Zielzustand.

**Triage-Entscheidung:** Agent Brief: [`briefs/ISSUE-11-token-aus-debug-output.md`](briefs/ISSUE-11-token-aus-debug-output.md)

**Erledigt am 2026-11-15:** kx-agent: Token-Feld kapselt den Debug-Output. Alle Akzeptanzkriterien abgehakt.
