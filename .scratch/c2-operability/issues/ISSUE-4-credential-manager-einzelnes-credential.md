---
id: ISSUE-4
title: extract_credential_manager liefert bei genau einem Credential eine leere Liste
status: done
category: bug
triage_state: erledigt
agent_brief: briefs/ISSUE-4-credential-manager-einzelfall.md
priority: medium
---

## Description

`extract_credential_manager` in `kx-win/src/secrets.rs` erzeugt unter Windows eine **leere Liste**, wenn genau ein Credential im Windows Credential Manager gespeichert ist.

Ursache: Das PowerShell-Skript (Zeile 45) verwendet `$results | ConvertTo-Json`. `ConvertTo-Json` serialisiert ein **einzelnes** Element als JSON-Objekt, nicht als Array. Der nachfolgende Aufruf `serde_json::from_str::<Vec<Secret>>(...)` scheitert daran und `unwrap_or_default()` liefert `Ok(vec![])`.

Bei zwei oder mehr Credentials funktioniert der Pfad, weil `ConvertTo-Json` dann ein Array erzeugt.

Konsequenz: Ein einzelnes gespeichertes Credential — der für einen Red-Team-Test häufigste Fall — wird übersehen. Die in den Contracts dokumentierte Zuordnung von `target` und `value` aus den `Target:`-/`User:`-Capture-Gruppen greift in diesem Fall ebenfalls nicht.

Verifiziert am 2026-11-11 per Quellcode-Prüfung (`kx-win/src/secrets.rs:45` und `:127`).

Related: ISSUE-3

## Acceptance Criteria

- [x] `extract_credential_manager` liefert bei genau einem gespeicherten Credential eine Liste mit einem Eintrag
- [x] Der Fehlerfall bleibt nachvollziehbar: ein JSON-Parse-Fehler führt zu einem `warn!`-Log statt zu einem stillen `Ok(vec![])`
- [x] Ein Test deckt den Ein-Fall und den Mehr-Fall ab (PowerShell-Ausgabe als String-Fixture, kein Windows-Zielsystem nötig)

## Technical Notes

- Betroffen: `kx/crates/kx-win/src/secrets.rs:45` (PowerShell-Skript) und `:127` (Parse-Schritt)
- Mögliche Lösungen: im Skript `@(...)` um `$results` klammern (erzwingt Array), oder `$results | ConvertTo-Json` mit `-AsArray` (PowerShell 7+), oder im Rust-Code einen Ein-Objekt-Fallback implementieren
- Die `-AsArray`-Variante setzt PowerShell 7 voraus; die Klammer-Variante funktioniert auch unter Windows PowerShell 5.1, das auf Zielsystemen häufiger vorliegt
- Achtung: `parse_secrets_from_json` verschluckt jeden Parse-Fehler (`unwrap_or_default()`) — das macht den Bug unsichtbar. Ein `warn!` bei Fehlern wäre die wichtigere Härtung

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der Fehler ist bestätigt: Die PowerShell-Sammlung wird serialisiert, ohne den
  Ergebniscontainer in einen Array-Zwang zu wrappen. Bei genau einem Element
  entsteht ein JSON-Objekt statt eines Arrays, der Deserialisierer erwartet eine
  Liste — das Ergebnis ist leer.
- Der stille Fehlerpfad ist ebenfalls bestätigt: ein Parse-Fehler führt nicht zu
  einer Log-Warnung.

**Triage-Entscheidung:** Agent Brief: [`briefs/ISSUE-4-credential-manager-einzelfall.md`](briefs/ISSUE-4-credential-manager-einzelfall.md)

**Erledigt am 2026-11-15:** kx-win: Credential-Manager liefert bei einem Credential eine Liste. Alle Akzeptanzkriterien abgehakt.
