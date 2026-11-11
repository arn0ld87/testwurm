---
id: ISSUE-6
title: GET /api/tasks liefert immer [] — Db::insert_task hat keinen Aufrufer
status: open
priority: medium
---

## Description

Der C2-Server legt die Tabelle `tasks` im Schema an (`CREATE TABLE IF NOT EXISTS tasks (...)` in `kx-server/src/db.rs`), und `GET /api/tasks` liefert sie aus. Der Schreibpfad fehlt aber vollständig:

`Db::insert_task` (`kx-server/src/db.rs:152`) wird von **keinem** Handler aufgerufen. Der Compiler meldet `method insert_task is never used`. Damit ist `GET /api/tasks` immer leer.

Konsequenz: Die in `kx/README.md` dokumentierte Fähigkeit, Aufgaben an kompromittierte Hosts zu verteilen, existiert nicht. Der `Task`-Pfad existiert nur im Protokollmodul `kx_core::c2` (`Task` mit `host_id`, `command`, `status`, `result`) und in der Datenbankschicht — es gibt weder eine Route zum Anlegen eines Tasks noch eine Verarbeitung auf Agent-Seite.

Related: ISSUE-7

## Acceptance Criteria

- [ ] Eine Route legt Tasks an (z. B. `POST /api/tasks`) und schreibt sie über `Db::insert_task`
- [ ] Der Agent ruft Tasks ab und führt sie aus — der `Task`-Typ existiert bereits im Protokollmodul, die Verarbeitung fehlt
- [ ] `GET /api/tasks` liefert angelegte Tasks
- [ ] Der Compiler meldet keine unbenutzte Methode mehr

## Technical Notes

- Betroffen: `kx-server/src/db.rs:152` (`insert_task`), fehlende Route in `kx-server/src/main.rs`, fehlende Abholung in `kx-agent/src/c2.rs`
- Der Protokoll-Typ `Task` trägt bereits `result: String` — das Feld für die Rückmeldung existiert
- Achtung: `insert_secret` und `insert_task` sind reine `INSERT`s ohne `ON CONFLICT` (`db.rs:120,152`) — eine doppelte Primärschlüssel-ID erzeugt `DbError::Sqlite`. Beim Anlegen von Tasks braucht es eine Idempotenz-Strategie, sonst bricht ein wiederholter Poll ab
- Der API-Vertrag ist versionierbar über `kx_core::c2` — die Routenkonstanten (`PATH_*`) liegen dort, ein neuer `PATH_TASKS` wäre dort zu ergänzen
