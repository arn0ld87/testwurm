---
id: ISSUE-6
title: GET /api/tasks liefert immer [] — Db::insert_task hat keinen Aufrufer
status: done
priority: medium
---

## Description

Der C2-Server legt die Tabelle `tasks` im Schema an (`CREATE TABLE IF NOT EXISTS tasks (...)` in `kx-server/src/db.rs`), und `GET /api/tasks` liefert sie aus. Der Schreibpfad fehlt aber vollständig:

`Db::insert_task` (`kx-server/src/db.rs:152`) wird von **keinem** Handler aufgerufen. Der Compiler meldet `method insert_task is never used`. Damit ist `GET /api/tasks` immer leer.

Konsequenz: Die in `kx/README.md` dokumentierte Fähigkeit, Aufgaben an kompromittierte Hosts zu verteilen, existiert nicht. Der `Task`-Pfad existiert nur im Protokollmodul `kx_core::c2` (`Task` mit `host_id`, `command`, `status`, `result`) und in der Datenbankschicht — es gibt weder eine Route zum Anlegen eines Tasks noch eine Verarbeitung auf Agent-Seite.

Related: ISSUE-7

## Acceptance Criteria

- [x] Eine Route legt Tasks an (`POST /api/tasks/new`) und schreibt sie über `Db::insert_task`
- [x] Der Agent ruft Tasks ab und führt sie aus — der `Task`-Typ existiert bereits im Protokollmodul, die Verarbeitung fehlt
- [x] `GET /api/tasks` liefert angelegte Tasks
- [x] Der Compiler meldet keine unbenutzte Methode mehr

## Technical Notes

- Betroffen: `kx-server/src/db.rs:152` (`insert_task`), fehlende Route in `kx-server/src/main.rs`, fehlende Abholung in `kx-agent/src/c2.rs`
- Der Protokoll-Typ `Task` trägt bereits `result: String` — das Feld für die Rückmeldung existiert
- Achtung: `insert_secret` und `insert_task` sind reine `INSERT`s ohne `ON CONFLICT` (`db.rs:120,152`) — eine doppelte Primärschlüssel-ID erzeugt `DbError::Sqlite`. Beim Anlegen von Tasks braucht es eine Idempotenz-Strategie, sonst bricht ein wiederholter Poll ab
- Der API-Vertrag ist versionierbar über `kx_core::c2` — die Routenkonstanten (`PATH_*`) liegen dort, ein neuer `PATH_TASKS` wäre dort zu ergänzen

## Umsetzung

Der Task-Fluss läuft jetzt über beide Enden:

- **Vertrag** (`kx-core/src/c2.rs`): `PATH_TASKS_CREATE` (`/api/tasks/new`),
  `PATH_TASKS_RESULT` (`/api/tasks/result`), die Request-Typen `CreateTaskRequest`
  und `TaskResultRequest` sowie die Task-Status `pending`, `running`, `done`,
  `failed`. Alle neuen Typen sind Request-Typen und damit lenient (ADR-0001) —
  ein älterer Server liest sie, ohne zu brechen.
- **Server** (`kx-server/src/main.rs`): `create_task` schreibt über
  `Db::insert_task` und liefert den angelegten Task als JSON zurück (201);
  `report_task_result` schreibt Status und Ergebnis über das neue
  `Db::update_task_result` zurück (200, bei unbekanntem Task 404).
- **Agent** (`kx-agent/src/tasks.rs`): `run_pending_tasks` holt `GET /api/tasks`,
  filtert auf eigene Host-Kennung und Status `pending`, führt das Kommando über
  die Shell aus (`sh -c` unter unix, `cmd /C` unter Windows) und meldet Status
  und Ausgabe zurück. Die Ausgabe wird auf 8 KiB gekürzt — an einer
  Zeichengrenze, damit kein UTF-8-Zeichen zerrissen wird.
- **CLI** (`kx-cli`): `kx-cli task-create --host-id <id> --command <befehl>` legt
  einen Auftrag an; vorher gab es keinen Weg, das ohne `curl` zu tun.

**Idempotenz:** `insert_task` bleibt ein reiner `INSERT` mit frischer UUID pro
Auftrag — ein wiederholter Poll legt keinen Doppel-Task an, weil der Agent
Tasks nur liest und meldet, nie anlegt. Die Ergebnisrückmeldung ist ein
`UPDATE` auf die Primärschlüssel-ID und damit von Natur aus idempotent.

**Verifikation** (Rocky Linux 10.2, x86_64, Rust 1.92.0):
`cargo fmt --check` grün, `cargo build --workspace --all-targets` grün,
`cargo test --workspace` grün (73 Tests, 0 Fehler). End-to-End gegen das
laufende System: `POST /api/tasks/new` ohne Token 401, mit Token 201,
`POST /api/tasks/result` 200, unbekannter Task 404, `GET /api/tasks` zeigt
`status: "done"` und das Ergebnis unter `result`.
