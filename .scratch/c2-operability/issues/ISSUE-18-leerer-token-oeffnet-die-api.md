---
id: ISSUE-18
title: Ein leeres Token oeffnet die C2-API ohne Authentifizierung
status: in-progress
priority: high
---

# ISSUE-18 — Ein leeres Token oeffnet die C2-API ohne Authentifizierung

## Description

Der C2-Server bestimmt sein Bearer-Token so:

```rust
let token = cli
    .token
    .or_else(|| std::env::var("KX_SERVER_TOKEN").ok())
    .unwrap_or_else(|| Uuid::new_v4().to_string());
```

Der Vergleich in `auth.rs` ist `constant_time_eq(kandidat, erwartungswert)`. Ist
der Erwartungswert leer, passt **jeder leere** `Authorization: Bearer `-Header
— die API antwortet dann mit Volldaten (`GET /api/secrets` liefert die
versiegelte Beute aller Hosts).

Zwei Wege führen in diesen Zustand:

1. `KX_SERVER_TOKEN=` (leer) in einer Environment-Datei — der übliche Weg,
   den Server per systemd zu starten. `std::env::var(...).ok()` liefert
   `Some("")`, nicht `None`.
2. `--token ""` auf der Kommandozeile.

Der Zufalls-Fallback hatte ein zweites Problem: er erzeugte einen Token, der
nirgends ausgeschrieben wurde. Ein so gestarteter Server war nicht
benutzbar — die README mahnte bereits, das Token immer explizit zu setzen.

Im Betrieb auf `rocky` (2026-11-16) war der Server über eine Environment-Datei
zu starten. Ein leerer Eintrag darin hätte die API geöffnet, ohne dass es
auffällt: Die Health-Prüfung mit einem Header meldet 200, der Rest der Kette
läuft weiter.

## Acceptance Criteria

- `kx-server` startet **nicht**, wenn kein Token gesetzt ist oder das Token
  leer ist (CLI oder Environment); Exit-Code ungleich 0, Meldung auf stderr.
- Ein gesetztes Token funktioniert unverändert: `--token` hat Vorrang vor
  `KX_SERVER_TOKEN`.
- Der Start ohne Token über eine Environment-Datei ist der empfohlene Weg und
  zeigt das Token **nicht** in der Prozessliste (`/proc/<pid>/cmdline`).
- Ein Unit-Test deckt die Fälle „leer", „nur Leerzeichen", „fehlt" ab.
- `README.md`, `CLAUDE.md` und `AGENTS.md` beschreiben das Token als Pflicht
  und nennen die Begründung.

## Technical Notes

- Die Aufloesung wandert in eine testbare Funktion `resolve_token(cli, env)`;
  `main()` bricht bei `None` ab. Ein Zufalls-Fallback entfaellt: ein Token,
  den niemand kennt, ist kein Token.
- Betroffen ist nur die Startkonfiguration, nicht der laufende Betrieb: Ein
  Server mit gesetztem Token hat den Vergleich `constant_time_eq` gegen einen
  nichtleeren Erwartungswert und lehnt jeden leeren Header ab.
- Verwandt: Der Token darf nicht als Kommandozeilenargument uebergeben werden
  (`/proc/<pid>/cmdline` ist fuer jeden Prozess lesbar). Auf `rocky` laeuft der
  Server deshalb per Environment-Datei mit `chmod 600`.
- Related: ISSUE-12 (API-Authentifizierung), ISSUE-11 (Token im Debug-Output)
