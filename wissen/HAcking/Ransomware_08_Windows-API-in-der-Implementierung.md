# Ransomware – Band 8: Windows-API in der Implementierung

Programmiertechnischer Band. API-Namen, Konstanten und typische Fehler. Quellen am Ende.

## 1. Treiber-Modell: wie ein realer Nachbau aufgebaut ist

Am Beispiel von **Lynx Ransomware** (Mitte 2024 aktiv, Source von INC gekauft) ist die Architektur dokumentiert und API-genau beschrieben [1] — gute Referenz für einen Nachbau, weil sie modern, nicht überkomplex und vollständig offengelegt ist.

Ablauf in dieser Reihenfolge:

```
CLI-Argumente parsen
  → Prozesse killen (optional)
  → Dienste stoppen (optional, rekursiv mit Dependants)
  → Write-Access-Check + Privileg-Eskalation
  → Shadow Copies auf jedem Laufwerk zerstören
  → Volumes mounten
  → Verzeichnisse enumerieren (rekursiv)
  → Dateien per IOCP-Threadpool verschlüsseln
  → Netzwerk-Freigaben separiert abarbeiten
  → Wallpaper + Print-Note
```

## 2. Prozess- und Dienstjagd

**Prozesse** [1]:
- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` → `Process32FirstW` / `Process32NextW`
- Namensabgleich case-insensitive gegen Substring-Liste. Lynx nutzt: `sql`, `veeam`, `backup`, `exchange`, `java`, `notepad`
- `OpenProcess(PROCESS_TERMINATE, …)` → `TerminateProcess`

**Dienste** [1]:
- `OpenSCManagerW` mit vollem Zugriff → `EnumServicesStatusExW`
- `OpenServiceW` mit `SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_STOP`
- `QueryServiceStatusEx` → `EnumDependentServices` → rekursiv erst Dependants stoppen, dann `ControlService(SERVICE_CONTROL_STOP)`

**Offene Dateien** — der elegante Weg, wenn eine Datei blockiert ist [1]:
- `RmStartSession` → `RmRegisterResources(datei)` → `RmGetList` liefert alle Prozesse mit offenem Handle
- `RmExplorer`- und `RmCritical`-Prozesse **auslassen**, eigene PID auslassen, dann `TerminateProcess` + `WaitForSingleObject`
- Das ist die **Restart-Manager-API** — deutlich präziser als Brachial-Kill nach Namensliste und in EDR-Signaturen seltener abgedeckt

**Freie Einordnung:** Namenslisten wie `sql|backup|veeam` sind der Grund, warum Datenbanken bei Ransomware-Wellen regelmäßig korrumpiert werden. Für den Eigenbau: Restart Manager bevorzugen, Kill-Liste auf wirklich offene Handles beschränken, Datenbankdienste nach Möglichkeit nur sanft stoppen.

## 3. Zugriffsrecht erzwingen

**Schreibzugriff testen** [1]:
- `SetFilePointerEx` ans Dateiende, 36 Bytes Dummy schreiben, geschriebene Bytezahl prüfen, Pointer zurücksetzen, `SetEndOfFile` zum Zurücktruncieren
- Achtung: das **verändert die Datei temporär auf dem echten Volume**. Saubere Alternative: `CreateFileW` mit `GENERIC_WRITE` und `OPEN_EXISTING` nur öffnen — Erfolg/Fehler reicht als Test, ohne Bytes zu schreiben (freie Einordnung).

**Privileg-Eskalation pro Datei** [1], die vollständige Kette:
1. `AllocateAndInitializeSid` für Zielgruppe
2. `EXPLICIT_ACCESS` (Full Control) → `SetEntriesInAclW` → neue DACL
3. `OpenProcessToken` → `LookupPrivilegeValueW("SeTakeOwnershipPrivilege")` → `AdjustTokenPrivileges` (aktivieren)
4. `SetNamedSecurityInfoW` mit `OWNER_SECURITY_INFORMATION` — Eigentümer setzen
5. `SetNamedSecurityInfoW` mit `DACL_SECURITY_INFORMATION` — Vollzugriff für eigene SID
6. `AdjustTokenPrivileges` wieder **deaktivieren** und DACL re-applizieren

**Wichtige Unterscheidung** [6][7]:

| Privileg | Wirkung | praktisch |
|---|---|---|
| `SeTakeOwnershipPrivilege` | Objekt-Eigentümer werden ohne discretionary access | der Lynx-Weg, braucht Admin/Delegate |
| `SeBackupPrivilege` | **Lesen** jeder Datei unabhängig von der DACL | Backup-Software-Weg, funktioniert auch auf geschützten Pfaden |
| `SeRestorePrivilege` | **Schreiben** und Eigentümer setzen unter DACL-Umgehung | erlaubt auch Writes in geschützte Bereiche |

**Freier Hinweis für den Eigenbau:** Ein Test-Implantat, das `SeBackupPrivilege`/`SeRestorePrivilege` im Token aktiviert (es ist auf Service-Konten mit Admin oft bereits gesetzt), kommt an deutlich mehr Dateien vorbei als einer, der ACLs umschreibt — und hinterlässt **keine ACL-Änderungen in der Forensik**. Das ist ein oft übersehener, großer Unterschied.

## 4. Volume- und Laufwerksbehandlung

- **Laufwerkserkennung:** `GetDriveTypeW` über `A:`–`Z:`, Typen `DRIVE_REMOVABLE`, `DRIVE_FIXED`, `DRIVE_REMOTE` akzeptieren, CD-ROM/Nichtexistentes verwerfen [1]
- **Volume-Handle:** `CreateFileW` mit Pfad **`\\?\A:\`** — das Präfix `\\?\` umgeht die normale Pfadparser-Semantik und erlaubt Pfade jenseits von `MAX_PATH` [1]
- **Alle Volumes mounten:** `FindFirstVolumeW`/`FindNextVolumeW` + `SetVolumeMountPointW` auf freie Buchstaben, erkannt an `DRIVE_NO_ROOT_DIR` [1] — so kommt man an nicht gemountete Volumes
- **Netzlaufwerke:** `WNetOpenEnumW`(`RESOURCE_GLOBALNET`, `RESOURCETYPE_ANY`) → `WNetEnumResourceW`, Treffer an `RESOURCEDISPLAYTYPE_SHARE`, rekursiv für `RESOURCEUSAGE_CONTAINER` [1]

## 5. Verzeichnis-Enumeration

Kernmuster [1]:
- `FindFirstFileW`/`FindNextFileW`, `.` und `..` überspringen, **Reparse Points überspringen** (Sonst: Junction-Schleifen auf `C:\Users\All Users`, `Documents and Settings`)
- Systemattribute und Extension-Blacklist prüfen (`.exe`, `.msi`, `.dll`, eigene Extension), eigene Binaries und Ransom-Noten aussparen
- `README`-Notiz pro Verzeichnis schreiben, rekursiver Abstieg pro Subdirectory
- Systemverzeichnisse pauschal meiden; `Program Files`/`Program Files (x86)` separat behandeln, darin gezielt nach Datenverzeichnissen (z. B. SQL-Instanzen) suchen [1]

**Freie Einordnung, typische Implementierungsfehler:**
1. **Junction-/Mount-Punkt-Schleifen** — ohne Reparse-Abarbeitung frisst die Enumeration sich selbst.
2. **Kein Long-Path-Support** — ohne `\\?\`-Präfix brechen tiefe Projektbäume still ab; „kein Fehler" ist hier das Problem, nicht ein Error-Code.
3. **Enumeration und Verschlüsselung in einem rekursiven Call** — bläht den Stack und blockiert den Threadpool. Besser: Work-Queue, ein Enumerationsthread, mehrere Worker.
4. **Keine Fehlerklassifikation** — `ERROR_SHARING_VIOLATION` (32), `ERROR_USER_MAPPED_FILE` (1224) und `ERROR_ACCESS_DENIED` (5) sind verschiedene Probleme mit verschiedenen Gegenmaßnahmen (Abschnitt 8).

## 6. Asynchrones I/O und Threadmodell

Lynx macht es so [1]:
- `GetSystemInfo` → **4 Threads pro Prozessor** als Verschlüsselungs-Fanout
- `CreateIoCompletionPort(NULL, …, 0, NumberOfProcessors)` — Port ohne Handle, Completion-Key 0
- Jede Datei: `ReadFile`/`WriteFile` mit `OVERLAPPED`, `switch_value` im `OVERLAPPED` als Zustandsmarker
- `CreateIoCompletionPort(dateiHandle, port, …)` assoziieren, Worker blockieren in `GetQueuedCompletionStatus` und schalten je nach Phase um
- Muster: 4 Zustände (erster Block, Folgeblock, Längen-/Restgrößenkorrektur, finaler Rename + Handle-Close)

Für `CreateFileW` gilt zusätzlich: **`FILE_FLAG_SEQUENTIAL_SCAN` erhöht die Performance bei sequenziellem Lesen großer Dateien deutlich**, auch wenn gelegentlich über kleine Bereiche gesprungen wird [2]. Genau das ist das Muster einer Partial-Verschlüsselung — also setzen, nicht weglassen.

**Freie Einordnung:** Der IOCP-Aufbau ist der aufwendigste Teil am ganzen Projekt und gleichzeitig der, an dem naive Nachbaue am häufigsten sterben. Für einen Schulungsnachbau: erst synchron mit festem Threadpool (M:N-Queue, ein Producer, N Worker) zum Laufen bringen, IOCP danach. Der Durchsatzunterschied ist real, aber die Fehlerquote steigt überproportional.

## 7. Partial Encryption mit Blockschritt — konkrete Parameter

Aus der Lynx-Analyse, 116 Byte Marker am Dateiende [1]:

| Feld | Größe | Inhalt |
|---|---|---|
| ECC/X25519 Public Key | 32 B | ephemer pro Datei |
| SHA-512(Public Key) | 64 B | Integritäts-/Identitätsanker |
| Magier `"LYNX"` | 4 B | Formatmarker |
| Unbekannt/Reserve | 4 B | `00 00 00 00` |
| Blockgröße | 4 B | `40 42 0F 00` = **1 000 000 ≈ 1 MB** |
| Blockschritt | 4 B | `05 00 00 00` = **5 MB Sprung** |
| Übersprungene Blöcke | 4 B | `01 00 00 00` |

Verschlüsselungsmuster: erste 1 MB, dann 1 MB ab Offset 6 MB, dann 1 MB ab 11 MB usw. — **1 MB verschlüsselt, 5 MB übersprungen** [1].

**Der schwierige Teil daran** [1]: Liest ein Worker 1 MB am Dateiende, rutscht er in den Marker hinein. Lynx rechnet `lpNumberOfBytesRead + next_enc_block_offset − filesize`, erkennt den Marker-Overflow (`0x74`) und zieht die Markergröße von der Schreiblänge ab. Genau diese Randfallmathematik ist die häufigste Quelle für korrupte Dateien in Eigenbauten.

**Freie Einordnung:** Für den Nachbau die Regel: **Marker niemals in die verschlüsselte Dateilänge hineininterpretieren.** Datei-Länge im Header/Manifest separat führen, Verschlüsselungsfenster aus der Manifest-Länge ableiten, nie aus `GetFileSize` der bereits teilveränderten Datei.

## 8. Fehlerbehandlungsmatrix

| Fehler | Code | Reaktion im Realbetrieb |
|---|---|---|
| `ERROR_ACCESS_DENIED` | 5 | `SeTakeOwnershipPrivilege`-Kette (Abschnitt 3), sonst verwerfen |
| `ERROR_SHARING_VIOLATION` | 32 | Restart Manager, kurz backoff, max. N Versuche — **kein Endlosloop** |
| `ERROR_DISK_FULL` | 112 | Abbruch-Flag global setzen, Journal schreiben, Rest als unverschlüsselt markieren |
| `ERROR_USER_MAPPED_FILE` | 1224 | SMB-Freigabe-Konflikt wie oben behandeln, Zweig zurückstellen |
| `ERROR_FILE_NOT_FOUND` / `PATH_NOT_FOUND` | 2 / 3 | Datei wurde verschoben — Entry aus Queue entfernen, kein Fehler |
| `ERROR_BAD_NETPATH` / Network down | 53 / 64 | Netzwerkzweig abbrechen, lokale Queue weiterlaufen lassen |
| `STATUS_INVALID_PARAMETER` auf Volume-Handle | — | Wechseldatenträger entfernt, Handle verwerfen |

Ohne diese Matrix hängt ein Implantat im Ernstfall an einer einzigen blockierten Datei fest — im Testlab mit sauberer Datenablage nie reproduzierbar (freie Einordnung).

## 9. Psychologie-Effekte in Code

- **Wallpaper:** Temporäres JPEG (z. B. `background-image.jpg`) schreiben, `SystemParametersInfoW(SPI_SETDESKWALLPAPER, …)` [1]
- **Print Bombing:** `EnumPrintersW`, „Microsoft Print to PDF" und „Microsoft XPS Document Writer" überspringen, dann `StartDocPrinterW` → `StartPagePrinter` → `WritePrinter` [1]
- **Extension + Ransom-Note pro Verzeichnis** — siehe Band 03
- Randfall Drucker: auf Headless-Servern existieren keine Drucker; der Code muss damit auskommen, ohne zu hängen

## 10. Neue Angriffsvariante: Sperren statt Verschlüsseln

**GhostLock** (Mai 2026, Open-Source-PoC von Kim Dvash): Ein Domain-User mit Normalrechten ruft `CreateFileW` mit **Sharing-Mode 0** auf und erhält damit einen exklusiven `deny-share`-Handle. SMB erzwingt diese Freigabe-Semantik serverseitig; kein anderer Prozess kann lesen, schreiben oder löschen, bis der Angreifer schließt [3].

- **500.000 Dateien auf einem Netzwerkshare in unter drei Minuten**, multithreaded parallel
- **Kein einziges Write-, Rename- oder Delete-Event** → Canary-Files, Tripwires, Write-Rate-Anomalien und DLP bleiben komplett still [3]
- Traffic-Profil unterscheidet sich nicht von einem Search-Indexer oder Backup-Job
- API einschränken ist unmöglich, bricht legitime Software; Detektion nur über Spezial-Telemetrie [3]

**Konsequenz für Bau und Abwehr (freie Einordnung):**
- Ein reiner Schreib-basierter Detektions- und Schutzansatz ist **unvollständig**. Locking-Angriffe gehören in jede Testmatrix.
- Für den Eigenbau ist `FILE_FLAG_DELETE_ON_CLOSE` plus Sharing-Mode 0 ein interessanter dritter Modus: **„Lock-Only-Run"** ohne Datenzerstörung — perfekt für Schulungsdemos mit rückstandsloser Rücknahme.

## Quellen

- [1] Nextron Systems – In-Depth Analysis of Lynx Ransomware (11.10.2024): https://www.nextron-systems.com/2024-10-11/in-depth-analysis-of-lynx-ransomware/
- [2] Microsoft Learn – CreateFileW (fileapi.h): https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- [3] GBHackers – Windows CreateFileW API Flaw Could Let Attackers Lock SMB Files at Scale (11.05.2026): https://gbhackers.com/windows-createfilew-api-flaw/ · Original: https://andreafortuna.org/2026-05-10/ghostlock/
- [6] Hacking Articles – SeRestorePrivilege: https://www.hackingarticles.in/windows-privilege-escalation-serestoreprivilege/ · SeBackupPrivilege: https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
- [7] Yunolay – Abusing SeBackupPrivilege and SeRestorePrivilege: https://blog.yunolay.com/sebackup-serestore-privilege/
- Querverweis: Band 03 (Technik & Krypto-Design), Band 04 (Detektion), Band 09 (Krypto-Implementierung)
