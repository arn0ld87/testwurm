---
id: ISSUE-5
title: demo_worm.rs Nutzungskommentar nennt nicht existierendes Flag --range
status: open
category: bug
triage_state: ready-for-agent
agent_brief: briefs/ISSUE-5-demo-worm-aufruf.md
priority: low
---

## Description

Der Nutzungskommentar im Beispiel-Binary `kx-exploit/examples/demo_worm.rs:6` dokumentiert einen Aufruf, der nicht funktioniert:

```
cargo run --example demo_worm -- --iface eth0 --range 192.168.1.1 192.168.1.254
```

Ein Flag `--range` existiert im Parser nicht. `Args` definiert ausschließlich `--iface`, `--start`, `--end`, `--own-ip`, `--hosts`, `--relay-script` und `--wmi-script` (`demo_worm.rs:21-26`). Der dokumentierte Aufruf bricht deshalb mit einem clap-Fehler ab (`unexpected argument '--range' found`).

Korrekt wäre `--start 192.168.1.1 --end 192.168.1.254`.

Verifiziert am 2026-11-11 per Quellcode-Prüfung.

## Acceptance Criteria

- [ ] Der Nutzungskommentar nennt einen Aufruf, der mit dem Parser übereinstimmt
- [ ] Der Kommentar enthält ein vollständiges, kopierbares Beispiel mit `--iface`, `--start` und `--end`

## Technical Notes

- Betroffen: `kx/crates/kx-exploit/examples/demo_worm.rs:6`
- Der Bug ist rein dokumentarisch, hat aber praktische Wirkung: wer den Kommentar übernimmt, startet das Beispiel nicht
- Sinnvoll wäre zusätzlich ein `--help`-Hinweis im Beispiel selbst (clap liefert das automatisch)

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der Nutzungskommentar des Beispiels nennt weiterhin ein Bereichs-Flag, das der
  Argument-Parser nicht kennt — er akzeptiert getrennte Start- und End-Angaben.
  Der kopierte Aufruf bricht mit einem Parser-Fehler ab.

**Triage-Entscheidung:** Agent Brief: [`briefs/ISSUE-5-demo-worm-aufruf.md`](briefs/ISSUE-5-demo-worm-aufruf.md)
