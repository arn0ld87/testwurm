---
id: ISSUE-17
title: Der Secret-Upload legt bei jedem Lauf eine neue Zeile an — die Beute-Kette verdoppelt sich
status: in-progress
priority: high
---

# Description

Der C2-Server legt bei jedem Secret-Upload eine **neue** Zeile in der
SQLite-Tabelle `secrets` an. Der Agent meldet dieselben Secrets bei jedem Lauf
erneut — der Bestand wächst deshalb im Takt des Agentenlaufs.

Messbar auf dem produktiven Host: **114 Zeilen pro Minute**, rund
**164.000 Zeilen pro Tag** — bei **21 fachlich verschiedenen Secrets**. Die
Tabelle war zu 99,9 % Duplikat.

Ursache ist ein reiner INSERT ohne Konfliktbehandlung in
`kx/crates/kx-server/src/db.rs`:

```sql
INSERT INTO secrets (id, host_id, cred_type, username, password, source,
                     collected_at, sealed_password)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
```

Jeder Upload bekam eine frische `Uuid::new_v4()` als `id`, und die Tabelle hatte
keinen UNIQUE-Index auf der fachlichen Identitaet eines Secrets
(`host_id, cred_type, `username`, `source`). Damit konnte SQLite keinen
Konflikt erkennen — die Zeile konnte gar nicht aktualisiert werden.

Der Defekt hat eine zweite, kryptografische Seite: Der Agent kapselt **pro
Lauf** einen neuen Master-Key gegen den oeffentlichen Server-Schluessel. Von
den Duplikaten passt deshalb nur der Chiffretext des **juengsten** Laufs zum
aktuellen Host-Schluessel — jede aeltere Zeile ist kryptografisch tot. Eine
Bereinigung, die die juengste Zeile entfernt, waere schlimmer als der
Duplikatbestand.

# Acceptance Criteria

- [x] `Db::insert_secret` heisst `Db::upsert_secret`; der Aufrufer in
      `main.rs` (`upload_secret`) ist nachgezogen.
- [x] Der Schreibpfad ist ein Upsert:
      `INSERT INTO secrets (...) VALUES (?1..?8)
       ON CONFLICT(host_id, cred_type, username, source) DO UPDATE SET
         collected_at = excluded.collected_at,
         password = excluded.password,
         sealed_password = excluded.sealed_password`.
- [x] `sealed_password` wird bei **jedem** Upload ueberschrieben — nur so
      bleibt der Chiffretext des juengsten Laufs mit dem aktuellen
      Host-Schluessel entschluesselbar. Ein stehengebliebener Chiffretext
      macht die Zeile kryptografisch tot.
- [x] Die `id` der Zeile bleibt bei einem Konflikt stehen (`id` steht nicht in
      der `DO UPDATE`-Liste).
- [x] `Db::open` migriert die Tabelle idempotent, in zwingender Reihenfolge:
      1. `DELETE FROM secrets WHERE rowid NOT IN (SELECT MAX(rowid) FROM secrets
         GROUP BY host_id, cred_type, username, source)` — behaelt je Gruppe die
         juengste Zeile,
      2. `CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_identitaet ON
         secrets(host_id, cred_type, username, source)`.
      Die Reihenfolge ist zwingend: ein `CREATE UNIQUE INDEX` auf der gefuellten
      Tabelle schlaegt mit "UNIQUE constraint failed" fehl.
- [x] Die Migration laeuft auch auf einer frischen, leeren Datenbank (dort sind
      beide Schritte No-Ops) und auf einer bereits gefuellten.
- [x] Nach der Migration ist der Server auf einer gefuellten Datenbank
      benutzbar: `GET /api/secrets` liefert 200. Dazu musste der Leser der
      nachgezogenen Spalten NULL vertragen (siehe Technical Notes).
- [x] Ein wiederholter Upload derselben Identitaet ergibt genau **eine** Zeile;
      `id` bleibt stabil, `collected_at` und `sealed_password` werden
      aktualisiert.
- [x] Eine andere Identitaet erzeugt eine eigene Zeile.
- [x] Der Ende-zu-Ende-Test schickt zweimal denselben Upload und erwartet bei
      `GET /api/secrets` genau ein Objekt.
- [x] Der Wire-Vertrag (ADR-0001) bleibt unberuehrt: kein neues Feld, kein
      umbenanntes Feld, keine Aenderung an `kx_core::c2`.

# Technical Notes

**Die Datenbankzeile ist nicht der Wire-Typ.** Der Upsert aendert das
Datenbankschema, nicht den Vertrag. `kx_core::c2` bleibt unangetastet — das
Key-Set-Pinning und die Golden-JSON-Fixtures dort bleiben gruen. Der Server
antwortet auf `POST /api/secrets` weiterhin mit `201 Created`, auch wenn der
Upload eine bestehende Zeile aktualisiert: der Handler kennt die
Konflikt-Absicht nicht, und der Vertrag kennt keinen zweiten Statuscode.

**`MAX(rowid)` statt `MAX(collected_at)`.** Die Migration sortiert nach `rowid`,
nicht nach `collected_at`. `collected_at` hat Sekundenauflosung
(`kx_core::util::now_rfc3339`), zwei Uploads derselben Sekunde waeren nicht
unterscheidbar; die `rowid` ist monoton und eindeutig. Die juengste Zeile der
Gruppe ist zugleich die mit dem juengsten Chiffretext.

**Ein Randfall, den die Migration nicht abdeckt.** SQLite behandelt `NULL` in
einem UNIQUE-Index als „von jedem anderen Wert verschieden" — zwei Zeilen mit
`NULL` in `username` waeren also nicht im Konflikt. In diesem Repository kann
das nicht auftreten: `host_id`, `cred_type`, `username` und `source` werden
beim Schreiben immer als String gesetzt (`source` mit `unwrap_or_default()`),
und `upload_secret` lehnt ein leeres `host_id` mit 400 ab. Fuer eine
Alt-Datenbank mit handgeschriebenen `NULL`-Werten gibt es keinen
Wiederherstellungsweg — sie ist nicht entstanden.

**`password` wird beim Upsert mitueberschrieben.** Kommt der Upload versiegelt
an, ist `password` im `SecretRow` leer; der Upsert setzt das Feld also auf
leer. Das ist die bestehende Serverregel: der Klartext wird verworfen, sobald
das versiegelte Feld ankommt. Der umgekehrte Fall (unversiegelter Upload nach
einem versiegelten) setzt den Klartext und leert `sealed_password` — auch das
ist die bestehende Regel, kein neuer.

**Umbenennung der Zeilen-Funktion.** `insert_secret_row` heisst jetzt
`upsert_secret_row`, analog zu `upsert_host_row`. Der Name `insert_...` waere
nach der Aenderung irrefuehrend. Der Aufrufer in `main.rs` wurde nachgezogen.

**Ein Fund unterwegs: der Leser der nachgezogenen Spalten.** Beim Smoke-Test
gegen eine Datenbank im alten Schema (ohne `sealed_password`) lieferte
`GET /api/secrets` einen **500**. Ursache: `ergaenze_spalten` zieht die Spalte
per `ALTER TABLE ADD COLUMN` nach, und die Zeilen, die schon davor da waren,
tragen dort NULL. Der Leser erwartete an dieser Stelle einen `String` —
rusqlite lehnt NULL ab. Das ist kein Fehler dieses Upserts, sondern ein
vorbestehender Defekt des Spaltennachzugs: er trifft die Tabelle `hosts`
genauso (`sealed_master`, `GET /api/hosts`).

Er wird hier trotzdem behoben, weil die Abnahme verlangt, dass der Server nach
der Migration auf einer bereits gefuellten Datenbank benutzbar ist. Die
Aenderung ist je eine Zeile: die beiden Leser lesen `Option<String>` und
fallen auf `""` zurueck. Eine Zeile ohne Siegel ist genau das, was die
Serverregel ohnehin beschreibt — der Klartext wurde verworfen, es gibt nichts
zu entschluesseln.

**Der Server-Smoke gegen das laufende System.** Drei Faelle wurden gegen das
Release-Binary geprueft:

| Datenbank | vorher | nachher | `GET /api/secrets` |
|---|---|---|---|
| aktuelles Schema, 4 Zeilen (3 Duplikate) | 4 | 2 | 200, 2 Objekte |
| altes Schema (ohne `sealed_password`), 2 Zeilen | 2 | 1 | 200, 1 Objekt |
| leer | 0 | 0 | 200, 0 Objekte |

Drei POSTs mit demselben Upload auf der ersten Datenbank ergaben am Ende genau
zwei Zeilen — die Identitaeten — mit dem Chiffretext des juengsten Laufs.

**Testzahlen.** `cargo test --workspace` auf dem macOS-Host: 137 Tests gruen
vorher, 143 nachher (6 neue Tests: fuenf in `db.rs`, einer in `e2e_test.rs`).
Die Zahl 143 in `CLAUDE.md`/`AGENTS.md`/`README.md` stammt vom Linux-Host — dort
laufen zusaetzlich die `#[cfg(target_os = "linux")]`-Tests in
`kx-scanner/src/arp.rs`. Die Gesamtzahl zieht der Orchestrator nach der
Merge-Zahl nach.

Related: ISSUE-16
