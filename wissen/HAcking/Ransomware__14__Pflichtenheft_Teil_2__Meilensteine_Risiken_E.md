# Ransomware · 14 · Pflichtenheft Teil 2 – Meilensteine, Risiken, Entscheidungen

# Ransomware – Band 14: Pflichtenheft Teil 2 – Abhängigkeiten, Meilensteine, Risiken

Stand August 2026. Fortsetzung von Band 13. Alle Aufwandszahlen sind **freie Schätzungen** in Personen-Tagen (PT) für eine einzelne entwickelnde Person und dienen der Reihenplanung, nicht der Budgetzusage.

## 1. Abhängigkeitsgraph

Die einzige Richtung, in der gebaut werden kann: **Format → Encoder → Journal → Beacon → Server → UI → Härtung.** Umgekehrte Reihen erzeugen Rewrite-Kaskaden.

```
M0 Korpus + Krypto-Formatvokabular
 │        (ohne festes Format ist jeder Encoder-Test wertlos)
 ├─→ M1 Krypto-Kern (DEK, KEM, Chunk-AEAD, Footer)
 │      └─→ M2 Encoder-Kern (enumerate → queue → workers → write)
 │             └─→ M3 Journal + Resume + Fehlerklassen
 │                    └─→ M4 Modus-Matrix (dry-run, lock-only, decrypt, purge)
 │                           └─→ M6 Standalone-Roundtrip-Abnahme ← GATE 1
 │
 ├─→ M5 Beacon + Task-Modell + Key-Escrow  (parallel ab M1 möglich)
 │        └─→ M7 Server + Schema + Rollen + Runs   ← GATE 2
 │
 └─→ M8 UI + Audit + Rate-Messung
            └─→ M9 Evasion + Build-Hygiene + YARA/AV-Matrix
                      └─→ M10 Härtung / Release
```

**Kritischer Pfad:** M0 → M1 → M2 → M3 → M4 → GATE 1 → M7 → GATE 2 → M10. Die Beacon-Strecke (M5) ist der einzige größere parallelisierbare Strang, weil sie an `/v1/escrow` und den Task-JSONs nur Verträge braucht, keine Encoder-Realität (freie Einordnung).

**Zwei Tore, hart:**
- **GATE 1 — Encoder vertrauenswürdig.** Band 12 §8 Punkte 1, 2, 4 erfüllt. Erst danach überhaupt an Multi-Host denken.
- **GATE 2 — Steuerstrecke vertrauenswürdig.** Task-Idempotenz, Escrow-ACK-Pflicht, Rate-Deckel, Rollen bewiesen. Erst danach auf reale Datenbestände loslassen.

## 2. Meilensteine

| M | Inhalt | Vorbed. | PT (Schätzung) | Austrittskriterium |
|---|---|---|---|---|
| **M0** | Goldener Korpus, Format-Skizze, Vektor-Tests, CI-Grundgerüst | – | 6–8 | Korpus mit allen Sonderformen aus B12 §2, Hashmanifest, CI läuft |
| **M1** | Krypto-Kern: Per-File-DEK, KEM, Chunk-AEAD, Header/Footer, Range-Liste, Trunkierungsschutz | M0 | 10–14 | Vektor-Test grün, Chunk-Umsortierung/-Trunkierung wird erkannt |
| **M2** | Encoder-Kern: Enumeration mit Reparse-/Long-Path-Regeln, Queue + Workerpool, `FILE_FLAG_SEQUENTIAL_SCAN`, Rate-Limit | M1 | 12–16 | Roundtrip über Teilkorpus, Handlezahl konstant, Rate hält Deckel ein |
| **M3** | Journal (JSONL, append-only), Resume, Fehlerklassen nach B08 §8, Backoff, Disk-Full-Pfad | M2 | 8–12 | Kill-mitten-im-Chunk besteht Roundtrip, Replay rekonstruiert Zustand |
| **M4** | Modi: `dry-run`, `lock-only`, `decrypt`, `purge`, Manifest-Verifikation pro Chunk | M3 | 6–9 | Modus-Matrix aus B13 §4 vollständig durchgetestet |
| **M5** | Beacon-Loop mit Jitter/Chunked-Sleep, Task-ID-Deduplizierung, Escrow-ACK, mTLS | M1 | 10–14 | Doppelzustellung wirkungslos, kein Start ohne ACK, keine Äquidistanz im Traffic |
| **M6** | **GATE 1** Standalone-Abnahme über ≥ 10.000 Dateien inkl. Crash, Idempotenz, Messprotokoll | M4 | 3–5 | B12 §8 Punkte 1, 2, 4, 6 bestanden |
| **M7** | **GATE 2** Server: Schema, Task-Queue mit Cancel, Runs, Events, Rollen, Key-Escrow mit Vier-Augen | M5, M6 | 14–18 | B12 §7 alle Fälle grün, Rollen erzwungen, Audit vollständig |
| **M8** | UI: Scopes, Run-Fortschritt, Fehlerlisten, Rate-Anzeige, Dry-Run-Report + Archiv | M7 | 8–12 | Operator kann Übung ohne Entwicklerhilfe fahren |
| **M9** | Evasion + Build-Hygiene: prozesslose VSS-Ioctl, String-Obfuskation, PDB-Trennung, YARA/AV-Matrix | M6 | 6–10 | keine Child-Prozesse, YARA-Lauf ohne Treffer dokumentiert |
| **M10** | Release-Härtung: Detektionsgegenprobe, Messprofile, Abnahme-Report, Betriebshandbuch | M8, M9 | 5–8 | B12 §6-Tabelle vorhanden, alle sechs Abnahmekriterien erfüllt |

**Summe:** rund 88–126 PT (~18–25 Wochen bei einer Person, 5-Tage-Woche). Ein zweiter Strang auf M5/M7 verkürzt den kritischen Pfad nicht um die Hälfte, aber M8+M9 lassen sich gut teilen (freie Schätzung).

**Was den Plan dominiert** (freie Einordnung): M3 ist der Meilenstein, an dem solche Projekte kippen. Journaling plus Resume ist unspektakulär und hat keinen sichtbaren Output — ohne ihn ist jeder Absturz ein Datenverlust, und genau das passiert auf echten Servern im Ernstfall ständig. Der zweitgrößte unterschätzte Block ist M7: Server, Rollen und Vier-Augen-Export sind viel Arbeit ohne sichtbaren Feature-Zuwachs, entscheiden aber über R4 und R8.

## 3. Test-Tore je Meilenstein

| Tor | Tests | Scheitern heißt |
|---|---|---|
| nach M1 | Chunk-Vektoren, Nonce-Folge, Trunkierung, Format-Roundtrip | Format neu schneiden, **nicht** um den Encoder herumbauen |
| nach M2 | Korpus-Teilmengen, Long Path, Junction, Junction-Schleife terminiert | Enumerationsdesign prüfen, bevor Worker dazu kommen |
| nach M3 | Crash nach 30 %, nach 70 %, mitten im Chunk, Disk-Full | kein Release-Kandidat, bis grün |
| nach M5 | Doppelzustellung, Netzausfall 1 h, Task mit Deadline, abgebrochener Task | Task-Modell korrigieren, bevor Server wächst |
| GATE 1 | B12 §8 komplett | keine Multi-Host-Aktion, kein Realbetrieb |
| GATE 2 | Rollen, Vier-Augen-Export, Rollout über 40 Hosts, Rate-Deckel | kein Produktivdateneinsatz |
| nach M10 | B12 §6 Detektionsmatrix inkl. Lock-only | Lücke dokumentieren statt kaschieren |

## 4. Risiken

| # | Risiko | W | A | Minderung |
|---|---|---|---|---|
| R1 | Stille Datenkorruption durch Chunk-/Nonce-Fehler, erst im Decryptor sichtbar | M | **H** | M0 Format-Vektor-Tests vor Encoderarbeit; pro Chunk Tag-Prüfung; goldener Korpus (B12 §2) |
| R2 | Marker-Randfall am Dateiende: die verschlüsselte Länge wird aus der Dateigröße falsch abgeleitet | **H** | M | Range-Liste im Manifest, Länge nie aus `GetFileSize` teilveränderter Datei ableiten (B08 §7) |
| R3 | Implantat hängt an einer blockierten Datei, Lauf stoppt still | M | M | Fehlermatrix E001–E003, Backoff mit Obergrenze, Restart Manager |
| R4 | Key-Escrow verliert Schlüssel durch Netzausfall zwischen Write und ACK | M | **H** | F004 ACK-Pflicht vor erstem Write; Escrow-Endpunkt separat monitoren |
| R5 | EDR/AV blockiert im Testbetrieb, das Projekt gilt als „funktioniert nicht“ | **H** | L | Signaturstrategie + Testmatrix B10 §3.6; Evasion explizit erst in M9 |
| R6 | Overhead pro Kleinstdatei real 50× schlechter als Laborwert | M | M | Benchmark mit Millionen Kleinstdateien (B12 §5), Rate-Deckel pro Scope |
| R7 | Steuerstrecke wird zum Flaschenhals bei 40+ Hosts (Thundering Herd) | M | M | Jitter auf Decrypt-Tasks, Batch-Reports, Fallback-Delays |
| R8 | Scope-Fehler erwischt Produktivverzeichnis | M | **H** | Dry-Run-Pflicht G006, Include/Exclude-Versionierung C001, Rollen G003 |
| R9 | Lock-only-Modus wird für „kein Risiko" gehalten und ohne Freigabe gefahren | L | M | Modus-Matrix als Vertrag, Handle-Hold-Zeit als Pflichtparameter |
| R10 | Projekt wächst um Linux/ESXi, während der Windows-Zweig noch instabil ist | M | M | POSIX-Zweig erst nach GATE 1, eigene Meilensteine; Windows-API-Bänder 08–10 decken ihn nicht ab |
| R11 | ETW/AMSI-Patch als „sicherer Trick" missverstanden | M | L | B10 §3.3: Patchen ist selbst detektierbares Artefakt; erst nach Messung |

W = Wahrscheinlichkeit, A = Auswirkung (L/M/H, freie Einschätzung).

## 5. Offene Entscheidungen

Bewusst noch nicht entschieden, weil sie Projektrichtung kosten:

| # | Entscheidung | Empfehlung | Begründung |
|---|---|---|---|
| E1 | Sprache Encoder: **C++ oder Rust** | **Rust**, wenn Linux/ESXi mitkommen soll, sonst C++ | B10 §1; Akira-Rust zeigt realen Cross-Platform-Nutzen, KEINE Detektionsmagie |
| E2 | Krypto-Bibliothek: BCrypt vs. libsodium | **libsodium**, BCrypt nur wenn FIPS-Modus Pflicht ist | B09 §1; modernere Defaults, kleiner Footprint |
| E3 | KEM: rein X25519 vs. hybrid ML-KEM-768 | Hybrid, aber in v1 abschaltbar | B09 §4; Migrationstest ohne Risiko |
| E4 | IOCP in v1 oder nicht | **Nein**, synchroner Pool zuerst | B08 §6; Fehlerquote steigt überproportional |
| E5 | Nur HTTPS vs. mTLS ab Tag 1 | mTLS ab Tag 1, auch im Lab | B11 §4; Zertifikatsverteilung ist die eigentliche Arbeit, nicht der Code |
| E6 | VSS-Behandlung: zerstören oder nur stilllegen | **stilllegen + Ioctl demonstrieren**, Zerstörung nur explizit | B08; Rückholbarkeit für Schulungsbetrieb |
| E7 | UI: Web-App oder CLI first | CLI first, Web-UI in M8 | B13 §8; jeder Modus muss offline allein funktionieren |
| E8 | Lock-only als eigener Modus bleiben? | **Ja**, unbedingt behalten | B08 §10, B12 §6; zeigt die blinde Stelle klassischer Abwehr |

## 6. Betriebshandbuch-Pflichtinhalte (für M10)

1. Scope anlegen → Dry-Run → Zahlen prüfen → scharf schalten (feste Reihenfolge, nicht optional)
2. Abbruch und Rücknahme in Notfallschritten, inkl. `--decrypt` ohne Server
3. Key-Escrow: Export mit Zweitperson, Verlustfall, was der Export kostet
4. Escalation: was tun, wenn Rate-Deckel den Übungsbetrieb ausbremst
5. Aufräumen: Journal, Manifeste, Restdateien, Handle-Reste nach Lock-only
6. Forensische Nachbereitung: welche Events das eigene Implantat hinterlassen hat — nützlich, weil sie genau zeigt, was eine Abwehr sehen würde

## 7. Was in v1 ausdrücklich nicht enthalten ist

1. Kein ETW-/AMSI-Patching (H004) — erst nach Messung, weil das Patchen selbst ein Artefakt ist.
2. Kein IOCP (E4) — der synchrone Pool muss zuerst alle Tore bestehen.
3. Kein Linux-/ESXi-Zweig vor GATE 1 (R10).
4. Keine Payment- und keine Lösegeldlogik, kein Ticket-System.
5. Keine Auto-Discovery neuer Hosts; Registrierung bleibt explizit `/v1/hello` mit Rolle aus dem Zertifikat.
6. Kein Hochverfügbarkeits-Setup für `app-server` und `key-escrow` — Voraussetzung dafür ist, dass die Standalone-Rücknahme (`--decrypt` ohne Server) nachweislich funktioniert. Ohne diesen Nachweis ist Einfachheit kein Argument, sondern ein Risiko. (freie Einordnung)

## Quellen

- Aufbauend auf Band 13 (Anforderungskatalog) und den Technikbändern 08–12
- Freie Schätzungen: alle PT-Angaben, Aufwandsverhältnisse, Risiko-Wahrscheinlichkeiten, Meilensteingewichtung
- Abnahmekriterien übernommen aus Band 12 §4 und §8
