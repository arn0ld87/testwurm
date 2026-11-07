# Ransomware – Band 12: Testharness, Messgrößen und Gegenprobe

Programmiertechnischer Band: womit man ein selbstgebautes Implantat messbar prüft, bevor man es auf echte Daten loslässt. Freie Einordnung, wo nicht anders vermerkt.

## 1. Warum ein Harness Pflicht ist

Ein Ransomware-Implantat hat eine Fehlerklasse, die sonst niemand hat: **sein Erfolg ist ein Schaden.** Ein normaler Agent darf beim hundertsten Lauf danebenliegen; ein Encoder, der in 3 von 100.000 Dateien den Chunk-Index falsch setzt, erzeugt dauerhaften Datenverlust, den erst der Decryptor nach Wochen zeigt. Ohne deterministischen Harness ist dieser Fehler nicht auffindbar (freie Einordnung).

## 2. Korpus-Design: was eine Testdatei sein muss

**Goldene Dateien** mit fester Bytegröße und bekanntem Inhalt (SHA-252-verifiziert):

| Kategorie | Zweck |
|---|---|
| 0 Byte | Deckt die „Datei zu klein zum Verschlüsseln"-Grenze ab |
| 1 Byte, halber Chunk, exakt ein Chunk | Chunk-Mathematik, Padding, Restlänge |
| ein Chunk + 1 Byte | der klassische Off-by-one-Fall |
| 255 MB / 4 GB / 8 GB + 1 Byte | Large-File-Pfade, `OVERLAPPED`-Offset über 32 Bit |
| Sparse File, hardlinkierte Datei | Raum- und Link-Semantik |
| Dateisystem-Junction / Mount-Punkt | Rekursionsschutz (Band 08 §5) |
| Datei mit offenem Handle (von extern gehalten) | `ERROR_SHARING_VIOLATION`, Restart Manager |
| Datei mit entzogener DACL, Eigentümer fremd | Privilegkette, `SeBackup`/`SeRestore` |
| NTFS-Alternate Data Stream, ADS-behaftete Datei | gehen bei naivem Copy-Delete oft verloren |
| Long Path > 260 Zeichen (ohne `\\?\`) | Long-Path-Regression |
| Datei mit Unicode-/Emoji-Namen, RTL-Zeichen | Encoding-Fehler, Anzeigefehler in der App |
| Read-only, Datei auf schreibgeschütztem Volume | Fehlerpfad, kein Hängenbleiben |
| Offenes DB-Abbild (MDF/EDB/VMDK) | Realitätsnähe Datenbanken |
| Binär mit geringer Entropie vs. bereits komprimiert | Entropie-basierte Heuristiken testen |

**Regel (freie Einordnung):** Jede gefundene Regression bekommt eine goldene Datei. Der Korpus ist damit nach einem halben Jahr der präziseste Dokumentationsgrad des Formats.

## 3. Determinismus

- Kein Zeitstempel aus der Uhr: Korpus mit **fix gesetztem** `mtime`/`ctime` erzeugen, sonst vergleichen Tests verschiedene Dateien.
- Zufallsquellen mit festem Seed; Krypto-Nonces dürfen **nicht** deterministisch sein — getrennt prüfen (Format deterministisch, Krypto probabilistisch mit After-the-fact-Verifikation).
- Reihenfolge der Queue ist ein Testgegenstand: Verschlüsselungsreihenfolge einmal alphabetisch, einmal randomisiert durchlaufen; das Ergebnis muss **bitidentisch** sein. Wenn nicht, steckt Zustand in den Workern.

## 4. Der zentrale Test: Roundtrip ohne Server

```
1. Korpus-Kopie anlegen + Manifest aller Hashes
2. implant --scope KOP --mode encrypt --dry-run   → Report prüfen, Hashes müssen unverändert sein
3. implant --scope KOP --mode encrypt             → Encoder läuft zu Ende
4. Hashes vergleichen: verschlüsselte Dateien MÜSSEN sich geändert haben,
   ausgeschlossene MÜSSEN identisch geblieben sein
5. implant --scope KOP --mode decrypt --keyfile …
6. Hashes gegen das Originalmanifest: 100 % Übereinstimmung, sonst fehlgeschlagen
7. Schritt 3–6 erneut, aber Prozess nach 30 % killen (Crash-Injektion)
   → Resume muss ohne Datenverlust fertigwerden
```

Der **Crash-Test in Schritt 7** ist der wichtigste Test der ganzen Liste und wird fast immer ausgelassen. Ein kill -9 / Stromausfall mitten im Chunk ist der Normalfall bei einem echten Vorfall, nicht der Sonderfall (freie Einordnung).

## 5. Last- und Realitätsprofil

Kennzahlen, die vor Produktivnutzung gemessen gehören:

| Messgröße | Zielgröße (freier Richtwert) |
|---|---|
| Durchsatz pro Kern (SSD, 1-MB-Chunks) | 300–900 MB/s bei AES-NI, sonst deutlich weniger |
| Skalierung über Kerne | sublinear ab ~8 Kernen akzeptabel, **kein** Rückgang |
| Datei-Overhead pro kleiner Datei | < 1 ms; bei Millionen Kleindateien dominiert das den Lauf |
| Latenz des Beacon-Sleeps auf Encoder-Reaktion | Pause muss innerhalb eines Sleep-Zyklus greifen |
| RAM pro Worker | konstant, keine Wachstumscurve pro Datei |
| Handle-Anzahl | muss auf den Workerpool zurückkommen, kein Leak über 100.000 Dateien |
| Netzwerk-Write auf SMB-Freigabe | unterhalb des vereinbarten Rate-Deckels |

**Warum Datei-Overhead wichtig ist:** Auf einem Dokumentenserver mit 2 Mio. Dateien à 30 KB ist nicht die Krypto das Problem, sondern `CreateFile`/`SetFileInformationByHandle`/Rename pro Datei. Wer nur große Dateien benchmarkt, bekommt eine Zahl um Faktor 50 zu optimistisch (freie Einordnung).

## 6. Gegenprobe: Detektion selbst messen

Es reicht nicht, das Implantat gegen Virenscanner zu werfen (Build-Matrix, Band 10 §3.6 [1]). Sinnvolle eigene Messung:

| Prüfen | Wie | Erwartung |
|---|---|---|
| Canary-File-Treffer | 3 versteckte Schreib-Ziel-Dateien im Scope | Treffer **vor** 1.000 verschlüsselten Dateien |
| VSS-Tampering-Sichtbarkeit | Sysmon-/ETW-Telemetrie auf `DeviceIoControl` | Event vorhanden, auch prozesslos |
| Entropie-Schreibrate | Summe ausgehender Schreibrate pro Fenster | Anstieg klar über Baseline |
| Rename-Burst | Anzahl `FileRenameInformation` pro Minute | Signal vorhanden, auch mit delay |
| Lock-only-Modus (GhostLock-artig) | Encoder startet nur Locks, keine Writes | **alle drei herkömmlichen Signale bleiben stumm** [2] |
| Beacon-Periodizität | Zeitreihenanalyse der Verbindungen | mit Jitter kein Äquidistanz-Signal |
| YARA | öffentliche CS-/Sliver-/Mythic-Regelsätze [1] | keine Treffer auf dem eigenen Binary |

Der Lock-only-Test ist der ehrlichste: Er zeigt, dass das eigene Erkennungsbild Lücken hat, die man vorher für theoretisch hielt — die GhostLock-Veröffentlichung belegt das für reale Abwehrarchitekturen [2].

## 7. Abbruch-, Rollout- und Rücknahme-Tests

- **Abbruch mitten im Lauf** → Manifest konsistent, Decryptor kommt mit teilweisem Zustand klar.
- **Server nicht erreichbar** während `encrypt` → Key-Escrow-Regel greift: kein Effektiv-Encrypt ohne bestätigten Key-Empfang (Band 11 §3).
- **Task doppelt zugestellt** → Idempotenztest: zweiter Durchlauf verändert nichts mehr.
- **Rate-Deckel zur Laufzeit ändern** → wirkt binnen eines Zyklus, ohne Abbruch.
- **Rollback über 40 Hosts gleichzeitig** → kein Thundering-Herd gegen den Server (Jitter auf Decrypt-Tasks nicht vergessen).
- **Neustart des Hosts mitten im Lauf** → Persistenz wiederholt, erkennt bereits verschlüsselte Dateien und macht sie nicht doppelt zu.

## 8. Acceptance-Kriterium für ein Schulungs-/Testtool

Freie Schwelle, an der ich ein Nachbauprojekt für brauchbar halte:
1. Roundtrip inkl. Crash-Injektion: **100 %.** Dateierhalt über einen Korpus von mindestens 10.000 Dateien mit allen Sonderformen aus Abschnitt 2.
2. Zweimaliges Ausführen ohne Zustandsänderung (Idempotenz) in 100 %.
3. Abbruchper Kommando binnen **eines** Beacon-Zyklus wirksam.
4. Key-Escrow nachweisbar vor der ersten Datenmutation im Server-Audit.
5. Lock-only-Modus ohne jede Datenänderung und ohne Rückstände außer den Handles.
6. YARA-/AV-Matrix dokumentiert, nicht nur „hat funktioniert".

## Quellen

- [1] ROBINX0 – Designing a Modern C2 Implant (Testmatrix: Defender, CrowdStrike, Elastic, öffentliche YARA-Regelsätze): https://robinx0.github.io/blogs/c2-development/implant-architecture-guide/
- [2] GBHackers – Windows CreateFileW API Flaw (GhostLock: keine Write-/Rename-/Delete-Events, Canary-Files wirkungslos): https://gbhackers.com/windows-createfilew-api-flaw/
- [3] Nextron Systems – Lynx-Analyse (konkrete Fehler- und Randfallbehandlungen als Vorbild): https://www.nextron-systems.com/2024-10-11/in-depth-analysis-of-lynx-ransomware/
- Querverweis: Band 08 (API-Fehlermatrix), Band 09 (Krypto-Randfälle), Band 10 (Build/YARA), Band 11 (Task-Invarianten), Band 04 (Detektionsseite)
