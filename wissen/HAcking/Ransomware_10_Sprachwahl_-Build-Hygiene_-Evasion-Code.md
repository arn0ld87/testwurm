# Ransomware – Band 10: Sprachwahl, Build-Hygiene und Evasion-Implementierung

Programmiertechnischer Band. Was welche Sprache real kostet, und wie Evasion konkret im Code aussieht. Quellen am Ende.

## 1. Sprachwahl — reale Befunde statt Geschmacksfrage

| Kriterium | C / C++ | Rust | Go |
|---|---|---|---|
| Reverse-Engineering-Hürde | niedrig–mittel (klare Konventionen) | **hoch** — Monomorphisierung, Traits, Boilerplate, `Release`-Optimierung | mittel (Großteil Runtime, aber typische Struktur) |
| Binary-Größe | klein, kontrollierbar | mittel (std + Monomorphisierung) | groß (GC + Runtime) |
| Abhängigkeiten | fast nur Win32 | Crates werden statisch eingeliukt — Akira-Rust brachte std + `seahorse`-CLI-Framework mit [3] | breite Standardbibliothek im Binary |
| Speicher-/Pufferfehler | Hauptquelle für Korruption | `unsafe`-Stellen bleiben riskant, Rest sicher | sicher, aber GC-Pausen |
| Signatur-Baseline | „normal" | VT-Erkennungsrate historisch auffällig; Rust-Flag oft erkannt | Go-Flag oft erkannt |
| Cross-Plattform (ESXi/Linux) | Portierungsarbeit | **stark** — Akira v2 traf damit ESXi-Bare-Metal [3] | stark |
| Build-Zeit / Toolchain | schnell | langsam (Linken, Monomorphisierung) | sehr schnell |

**Belegter Befund zur These „Rust ist schwerer zu analysieren":** Check Point hat Akiras Rust-Variante systematisch analysiert und zeigt, wie Rust-Idiome, Boilerplate und Compilerstrategien zusammenspielen und das Assembly verkomplizieren [3]. Zugleich zeigt dieselbe Analyse: die üblichen Forschungsfragen („welche Extensions?", „welche Krypto?") sind auch ohne komplette Assemblerückgewinnung beantwortbar [3]. **Die Hürde ist **Die Hürde ist also real, aber endlich** — kein Unsicherheitsfaktor, der ein Projekt trägt.

**Umkehrschluss für den Eigenbau (freie Einordnung):**
- **C++ oder Rust** für den Encoder — Windows-API-Zugriff ohne Laufzeit-Ballast, voller Kontrolle über Puffer und I/O.
- **Rust** wenn Cross-Platform (Windows + Linux/ESXi) von Anfang an auf der Liste steht — genau Akiras Motivlage [3].
- **Go** nur, wenn die Steuerungsapp/Server-Komponenten den größeren Teil der Arbeit machen und das Implantat nur „einfach funktionieren" muss. Der Go-Footprint im Implantat ist ein echter Nachteil.
- Die Sprache macht vielleicht 5 % der Detektionslage aus; **Signaturen entstehen durch Konfigurationsblöcke, Strings und Konstanten**, nicht durch den Compiler (freie Einordnung).

## 2. Build-Hygiene

Pflichtliste (freie Einordnung, Praxis Standard):
- `Release`-Optimierung, **PDBs Separat halten**, nie mit ausgeliefertem Binary; Quellpfade im Binary prüfen (`/Zi` + `/Fd`, bei Rust `strip`, `panic=abort`, `lto=true`, `codegen-units=1`)
- **Kein Build-Reproducibility-Leak**: Pfad, Username, Zeitstempel im PE — bei jedem Testlauf anders, bei jedem Kunden gleich und damit gruppentypisch
- **Per-Build-Schlüssel** für String-Obfuskation, **nicht statisch** [1]
- Compilieren gegen **ältester Ziel-SDK**, die bedient werden soll — `bcrypt`/`advapi32`-Signaturen sind stabil
- PE-Header-Metadaten (Produktname, Firma, Version) **fälschen oder löschen**; Subsystem, Linker-Version und Section-Entropie gegen eigene Baseline prüfen
- **Signatur-Strategie** für den Testbetrieb festlegen: un Signaturen + SmartScreen + AV-Cloud-Lookup entscheiden, ob das Implantat im Test überhaupt startet

## 3. Evasion im Code — konkret implementiert

Aus dem C2-Architekturleitfaden [1], API-genau:

### 3.1 String-Verschlüsselung
Klartext-Strings vermeiden; Mindestmaß Compilezeit-XOR mit **per-Build-Schlüssel**, Entschlüsselung nur bei Bedarf, danach `memset` auf 0 und `free` [1].

### 3.2 API-Hashing
API-Namen nicht im Import-Table-String ablegen: Hash konstant halten (`djb2`-Muster), zur Laufzeit **PEB → LDR → Modul-Liste → Export-Tabelle** durchlaufen, Exportnamen hashen, vergleichen [1]. Effekt: Import-Table-Analyse und einfache YARA-Strings brechen weg.

### 3.3 ETW-Patch
```
etw = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
VirtualProtect(etw, 1, PAGE_READWRITE, &old);
*(BYTE*)etw = 0xC3;           // ret
VirtualProtect(etw, 1, old, &old);
```
Vor jeder Ausführung patchen [1]. AMSI analog (`AmsiScanBuffer`). **Achtung:** In-process-Patching ist selbst ein detektierbares Artefakt (Instruction-Integrity-Checks, `EtwEventWrite`-Prolog-Vergleich) — freie Einordnung.

### 3.4 Memory-Indikatoren
Für eigene Implantate [1]:
- XOR-Schlüssel pro Build statt statisch
- PE-Header randomisieren oder nach dem Laden löschen
- keine gemeinsamen Magic Bytes in Konfigurationsblöcken
- Strukturen über **nicht-kontinuierliche** Allokationen fragmentieren

### 3.5 Prozessmodell
- **In-Process-Ausführung bevorzugen**: keine Child-Prozesse, kein `cmd.exe`, kein `powershell.exe`; BOFs/Inline-Ausführung/Direkt-Syscalls für kritische Aufrufe [1]
- Fork-and-run erzeugt Telemetrie: Event 4688, Sysmon 1, Parent-Child-Anomalien [1]
- CLR-Artefakte: einmal geladene .NET-Runtime ist **nicht** entladbar [1]
- Injection-Zielwahl [1]: `svchost.exe` (niedrig–mittel) und `RuntimeBroker.exe` (niedrig) brauchbar; `notepad.exe` **hoch** — keine Netzwerkaktivität erwartet; `cmd.exe`/`powershell.exe` kritisch

### 3.6 Testmatrix vor Produktivnutzung
Defender → CrowdStrike Falcon (aggressives Hooking) → Elastic Security (offene Regeln) → **YARA**: öffentliche CS-/Sliver-/Mythic-Regelsätze gegen das eigene Binary laufen lassen [1].

## 4. Kein Child-Process, aber trotzdem Reporting

Freie Einordnung, typische Architektur-Entscheidung: Ein Ransomware-Implantat, das VSS über `vssadmin.exe` löscht, erzeugt Prozess-Telemetrie und Skript-Clutter. Der API-Weg über `DeviceIoControl` (IOCTLs, siehe Band 08) und VSS-Kom-API bleibt prozesslos. **Regel: alles, was per API geht, nie per Kindprozess starten.** Lynx nutzt etwa `DeviceIoControl` mit Control-Code `0x53C028` (`IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE`, Max-Größe 1), statt `vssadmin` aufzurufen [5].

## 5. Was Detektion trotzdem auslöst

Auch mit ETW-Patch und Syscalls bleibt Verhalten sichtbar (Band 04): Entropie-Schreibrate, Rename-Bursts, VSS-Tampering, Zugriffsmuster über viele Verzeichnisse in kurzer Zeit. **Freie Einordnung:** Evasion verschiebt das Fenster um Sekunden bis Minuten — genau das Fenster, das die Abwehr für Stoppen und Isolieren braucht. Wer Evasion ohne Zeitbudget betreibt, optimiert an der Realität vorbei.

## Quellen

- [1] ROBINX0 – Designing a Modern C2 Implant: Architecture and OPSEC (20.03.2026): https://robinx0.github.io/blogs/c2-development/implant-architecture-guide/
- [3] Check Point Research – Inside Akira Ransomware's Rust Experiment (03.12.2024): https://research.checkpoint.com/2024/inside-akira-ransomwares-rust-experiment/ · Folgereferenz: Rust Binary Analysis Feature by Feature
- [5] Nextron Systems – In-Depth Analysis of Lynx Ransomware (DeviceIoControl 0x53C028): https://www.nextron-systems.com/2024-10-11/in-depth-analysis-of-lynx-ransomware/
- Querverweis: Band 04 (Evasion/Detektion), Band 08 (Windows-API), Band 11 (C2/Steuerungsapp)
