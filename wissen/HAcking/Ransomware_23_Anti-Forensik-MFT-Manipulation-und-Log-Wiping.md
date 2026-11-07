# Ransomware – Band 23: Anti-Forensik, MFT-Manipulation und Log-Neutralisierung

Technischer Deep Dive: NTFS-Metadatenmanipulation ($MFT, $STANDARD_INFORMATION vs. $FILE_NAME), $UsnJrnl-Bereinigung, VSS-Sabotage, EventLog-Thread-Suspension, Ausführungsartefakte (Amcache, Shimcache) und forensische Gegenrekonstruktion.

---

## 1. NTFS-Metadaten und Timestomping-Mechanik

Um nach einer lateralen Bewegung oder dem Platzieren von Malware-Payloads die Erstellung von Zeitachsen (Timelines) durch Incident-Response-Teams zu sabotieren, manipulieren Angreifer die Zeitstempel im Dateisystem.

```
+----------------------------------------------------------------------------+
| Anatomie eines NTFS $MFT File Record (1024 Bytes)                          |
+----------------------------------------------------------------------------+
| [ Record Header: 'FILE' Magic (0x454C4946), Offsets, Update Sequence ]     |
|                                                                            |
| [ Attribut 0x10: $STANDARD_INFORMATION ]                                   |
|   - Created (C), Modified (M), MFT Altered (A), Read (R)                   |
|   - Sichtbar im Windows Explorer und modifizierbar via SetFileTime API     |
|   - Angreifbar durch Standard-Timestomping                                 |
|                                                                            |
| [ Attribut 0x30: $FILE_NAME ]                                              |
|   - Eigene C/M/A/R Zeitstempel                                             |
|   - Wird NUR vom NTFS-Kernel-Treiber bei Dateioperationen aktualisiert     |
|   - Unverändert bei API-Aufrufen von SetFileTime()                         |
|                                                                            |
| [ Attribut 0x80: $DATA ]                                                   |
|   - Eigentlicher Dateiinhalt (Resident oder Non-Resident Cluster Runs)     |
+----------------------------------------------------------------------------+
```

### 1.1 MACB-Zeitstempel und das Attribut-Dilemma

NTFS speichert für jede Datei vier Zeitstempel:
- **M**odified: Letzte Inhaltsänderung.
- **A**ccessed: Letzter Lesezugriff (unter modernen Windows-Versionen standardmäßig oft deaktiviert zur Performanceoptimierung).
- **C**reated: Erstellungszeitpunkt der Datei.
- **B**orn / MFT Altered: Letzte Modifikation des MFT-Records selbst.

#### Naives Timestomping via Win32-API
Standard-Angriffswerkzeuge rufen die Windows-API `SetFileTime()` auf:
```c
// Typischer naiver API-Aufruf:
HANDLE hFile = CreateFileW(L"C:\\malware.exe", FILE_WRITE_ATTRIBUTES, ...);
FILETIME ft; // Kopiert von kernel32.dll (z. B. aus dem Jahr 2021)
SetFileTime(hFile, &ft, &ft, &ft);
CloseHandle(hFile);
```
**Die forensische Schwachstelle:** `SetFileTime()` modifiziert ausschließlich die Zeitstempel im Attribut **$STANDARD_INFORMATION (0x10)**. Das Attribut **$FILE_NAME (0x30)** bleibt unberührt auf dem tatsächlichen Erstellungszeitpunkt (z. B. November 2026).

#### Forensische Erkennung via MFT-Divergenz
Forensiker (z. B. mit Eric Zimmermans `MFTECmd` oder `analyzeMFT`) vergleichen beide Attribute:
$$\Delta t = t(\$STANDARD\_INFORMATION.\text{Created}) - t(\$FILE\_NAME.\text{Created})$$
Liegt $\Delta t > 0$ (d. h. der sichtbare Erstellungszeitpunkt liegt zeitlich **vor** dem Dateinamen-Eintrag im Kernel), liegt zweifelsfrei Timestomping vor.

#### Fortgeschrittenes Timestomping (Raw MFT Write)
Um auch `$FILE_NAME` zu manipulieren, müssen Angreifer:
1. Den Volume-Schutz umgehen und ein Raw-Handle auf das Volume anfordern (`CreateFile` auf `\\.\C:` mit `GENERIC_WRITE`).
2. Den Volume File Record Record im `$MFT` direkt lokalisieren und die Bytes im 0x30-Attribut bitgenau patchen.
3. Erfordert administrative Rechte und wird häufig durch Kernel-Minifilter oder EDR-Treiber blockiert.

---

## 2. Beseitigung von Transaktionsjournalen

Das NTFS-Dateisystem protokolliert Operationen hochgradig redundant. Ein einfaches Löschen einer Datei hinterlässt Spuren im Journal.

### 2.1 $UsnJrnl (Update Sequence Number Journal)

Das USN-Journal (`$Extend\$UsnJrnl:$J`) speichert chronologisch jede Dateiänderung, Erstellung und Löschung zusammen mit dem Grund (`USN_REASON_FILE_CREATE`, `USN_REASON_DATA_OVERWRITE`).
- Selbst wenn eine Datei gelöscht und ihr MFT-Eintrag freigegeben wird, belegt der USN-Eintrag die Existenz und den Pfad der Datei.
- **Angriffsmechanik:** Vor und nach der Verschlüsselung führen Ransomware-Loader folgende Befehle aus:
  ```cmd
  REM Deaktiviert und löscht das USN-Journal vollständig:
  fsutil usn deletejournal /d /n C:
  ```
  Dadurch wird der Sparse-Datenstream `$J` komplett abgeschnitten und neu initialisiert.

### 2.2 $LogFile (Transaktionsprotokoll)

Das `$LogFile` sichert Transaktionskonsistenz bei Systemabstürzen. Es speichert Redo- und Undo-Operationen. Ein Überschreiben erfordert Raw-Volume-Zugriff oder das gezielte Erzwingen von Journal-Wrap-Arounds durch massenhaftes Erzeugen und Löschen von Dummy-Dateien.

---

## 3. Volume Shadow Copies (VSS) Vernichtungspfade

Um die Wiederherstellung verschlüsselter Daten ohne Erpresser-Key zu vereiteln, eliminieren Ransomware-Gruppen alle Schattenkopien.

```
+-------------------------------------------------------------------+
| Schattenkopien-Löschmethoden im Vergleich                        |
+-------------------------------------------------------------------+
| 1. vssadmin CLI:                                                  |
|    vssadmin delete shadows /all /quiet                            |
|    Detektion: Extrem hoch (Sigma-Regeln auf Process Creation)     |
|                                                                   |
| 2. WMI CLI / WMIC:                                                |
|    wmic shadowcopy delete                                         |
|    Detektion: Sehr hoch (CommandLine Argument Monitoring)         |
|                                                                   |
| 3. PowerShell CIM:                                                |
|    Get-CimInstance Win32_ShadowCopy | Remove-CimInstance          |
|    Detektion: Hoch (Script Block Logging Event ID 4104)           |
|                                                                   |
| 4. VSS COM-API (IVssBackupComponents):                            |
|    Direkter C++ Aufruf von DeleteSnapshots()                      |
|    Detektion: Niedrig (kein CLI-Prozess-Spawn, reiner API-Call)   |
|                                                                   |
| 5. Shadowstorage Resize (Stille Deallokation):                    |
|    vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB    |
|    Detektion: Mittel (erzwingt VSS-Löschung wegen Platzmangel)    |
+-------------------------------------------------------------------+
```

---

## 4. Windows Event-Log Neutralisierung ohne Service-Crash

Das einfache Löschen von Windows-Ereignisprotokollen über das administrative Hilfsprogramm `wevtutil cl System` oder `wevtutil cl Security` ist forensisch kontraproduktiv:
- Das Löschen erzeugt zwingend **Event ID 1102** ("The audit log was cleared") im Security-Log.
- Jedes SIEM-System generiert daraufhin sofort einen Alarm mit höchster Kritikalität.
- Das Beenden des EventLog-Dienstes (`svchost.exe -k LocalServiceNetworkRestricted`) ist durch Windows geschützt und erzeugt beim Killen **Event ID 7034** (Service Crash).

### 4.1 Die elegante Methode: EventLog Thread Suspending

Der Windows EventLog-Dienst läuft innerhalb einer `svchost.exe`-Instanz. Statt den Prozess zu terminieren, identifizieren Angreifer die spezifischen Threads, die für das Schreiben von Events zuständig sind, und frieren sie ein:

```
+-----------------------------------------------------------------------+
| Ablauf der Thread-Suspension im EventLog-Dienst                       |
+-----------------------------------------------------------------------+
| 1. OpenSCManager / OpenService -> Ermitteln des Ziel-Dienstes         |
| 2. QueryServiceStatusEx -> Ermitteln der Ziel-PID von svchost.exe     |
| 3. OpenProcess(PROCESS_ALL_ACCESS) auf die Ziel-PID                   |
| 4. CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) aller Threads          |
| 5. Filtern: Threads, deren Call-Stack auf wevtsvc.dll zeigt           |
| 6. OpenThread(THREAD_SUSPEND_RESUME) -> SuspendThread() aufrufen     |
| Ergebnis: Der Dienst 'EventLog' gilt für Windows weiterhin als AKTIV, |
|           aber es werden KEINE neuen Events mehr geschrieben!         |
+-----------------------------------------------------------------------+
```

Da der Dienst aus Sicht des Service Control Managers (SCM) den Status `SERVICE_RUNNING` behält, schlägt kein Service-Crash-Alarm an und es wird kein Event 1102 generiert.

---

## 5. Beseitigung flüchtiger Ausführungsartefakte

Windows hinterlegt Programmausführungen an zahlreichen redundanten Orten:

### 5.1 Shimcache (AppCompatCache)
- **Pfad:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
- **Funktion:** Sichert Kompatibilitätsdaten ausgeführter Binärdateien (Dateipfad, Dateigröße, letzter Modifikationszeitpunkt).
- **Bereinigung:** Der Shimcache wird primär im Kernel-Speicher gehalten und erst beim System-Shutdown in die Registry geschrieben. Angreifer manipulieren den Speicherwert oder erzwingen einen Dirty Reboot (BSOD via `NtRaiseHardError`), um das Schreiben zu verhindern.

### 5.2 Amcache.hve
- **Pfad:** `C:\Windows\appcompat\Programs\Amcache.hve`
- **Funktion:** Eigene Registry-Hive-Datei, die SHA1-Hashes ausgeführter Programme, Compile-Timestamps und Installationspfade persistiert.
- **Bereinigung:** Da die Datei vom System exklusiv gesperrt ist, greifen Angreifer über Volume Shadow Bypasses oder Pre-Boot-Skripte darauf zu.

### 5.3 Prefetch-Dateien
- **Pfad:** `C:\Windows\Prefetch\*.pf`
- **Funktion:** Beschleunigt Anwendungsstarts, speichert Ausführungszähler, letzte 8 Ausführungszeitpunkte und geladene DLLs.
- **Löschung:** `del /f /q C:\Windows\Prefetch\*.pf`

---

## 6. Forensische Gegenrekonstruktion

Erfahrene Incident-Response-Teams können Aktivitäten trotz Anti-Forensik rekonstruieren:

```
+-----------------------------------------------------------------------+
| Forensische Triage-Matrix bei Log-Verlust                             |
+-----------------------------------------------------------------------+
| Artefakt                Forensischer Ersatzwert                       |
+-----------------------------------------------------------------------+
| Gelöschtes EventLog     NetFlow / Firewall Logs / Switch Port Mirrors  |
| Gelöschtes MFT-Record   $I30 Verzeichnis-Index B-Tree Slack Space     |
| Gelöschtes Prefetch     Memory Dump (Volatility: malfind, pslist)     |
| Gelöschtes USN-Journal  $LogFile Transaktions-Carving                 |
| Manipulierte Zeit       MFT $FILE_NAME Attribut vs. Registry-Key-Zeit |
+-----------------------------------------------------------------------+
```

### 6.1 Kernschritte der Incident Response
1. **Volatilen Speicher sichern:** Vor jedem Herunterfahren muss ein vollständiger RAM-Dump (z. B. via LiME oder WinPmem) erstellt werden. Aktive Injektionen und C2-Verbindungen sind nur im RAM unmanipuliert nachweisbar.
2. **$I30 Slack Carving:** Wenn eine Datei gelöscht wird, verbleibt der Dateiname oft als verwaister Index-Knoten im Verzeichnis-Index `$I30`.

---

## Quellen
- [Q3] MITRE ATT&CK – T1486 Data Encrypted for Impact
- [Q66] Volatility Foundation – Volatility 3 Memory Forensics Framework
- [Q77] SANS Institute – Memory and Storage Anti-Forensics Analysis
- [Q78] Eric Zimmerman – Tools and Guidance for NTFS Analysis (MFTECmd)
- [Q79] Microsoft Learn – Master File Table (MFT) Architecture Reference
