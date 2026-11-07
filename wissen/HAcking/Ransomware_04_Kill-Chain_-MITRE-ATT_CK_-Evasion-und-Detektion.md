# Ransomware – Band 4: Kill Chain, MITRE ATT&CK, Evasion und Detektion

Stand August 2026. Quellen am Ende.

## 1. Phasenmodell aus Verteidigersicht

Picus Security beschreibt den ransomware-spezifischen Ablauf in Phasen inkl. einer **Early-Warning-Phase** nach dem Initial Access, in der Persistenz angelegt, System erkannt, Daten gesammelt und Fähigkeiten ausgebaut werden – und zwar mit ATT&CK-Techniken unter Persistence, Privilege Escalation und Defense Evasion [1]. Für die Praxis gilt: **die verschiebbare Zeit liegt vor der Verschlüsselung, nicht danach.**

| Phase | Was der Angreifer tut | bester Abwehrhebel |
|---|---|---|
| 1 Initial Access | Phishing, Identitätsmissbrauch, VPN/RDP, Edge-Geräte, Lieferant | MFA, Conditional Access, Proxy-/Zertifikatshärtung |
| 2 Early Warning / Aufbau | Persistence, Discovery, Credential Dumping, Data Staging | EDR-Alerting, Honeytokens, Least Privilege |
| 3 Laterales & Escalation | Admin-Shares, RDP, GPO, Domain-Admin-Pfad | Segmentierung, Tier-Modell, JourneyPaths |
| 4 Exfiltration | Komprimieren, Staging, Cloud-Upload, Exfil über Ports | Egress-Control, DLP, Volumenanomalie |
| 5 Inhibit Recovery | VSS löschen, Backup-Cataloge, Snapshots | Offline-/Immutable-Kopien, Command-Line-Audit |
| 6 Impair Defenses | EDR/AV deaktivieren, agentlos arbeiten | TAMPER-Protection, Konfigurationsdrift-Alarm |
| 7 Encryption / Impact | T1486, Rename, Ransom-Note, Print Bombing | Canary-Files, Entropie-Rate, Rate-Limiting von Schreibbatches |

## 2. Relevante MITRE-ATT&CK-Techniken (Referenzliste)

- **T1486 – Data Encrypted for Impact** (Tactic Impact, Impact Type Availability, Plattformen Windows/Linux/macOS/ESXi/IaaS). Typischerweise werden Office-Dokumente, PDFs, Bilder, Videos, Audiodateien, Texte und Quellcode verschlüsselt sowie umbenannt und mit Markern versehen. Vorbehaltene Verhaltensweisen: **T1222 File and Directory Permissions Modification** und **T1529 System Shutdown/Reboot**, um Dateien überhaupt öffnen zu können; teils Verschlüsselung von Systemdateien, Partitionen und MBR; VMs auf ESXi; Cloud-Storage-Objekte in kompromittierten Accounts. Einschüchterung über **T1491.001 Internal Defacement** (Wallpaper, ESXi-Login-Banner) oder **"Print Bombing"** [2].
- **Wurmartige Ausbreitung** von Encryption-Malware nutzt **T1078 Valid Accounts**, **T1003 OS Credential Dumping** und **T1021.002 SMB/Windows Admin Shares** [2].
- **T1490 – Inhibit System Recovery** (VSS, Backups, Recovery-Konsole) [3].
- **T1562 – Impair Defenses** als Defense-Evasion-Standard in der späten Phase: Sicherheitssoftware stilllegen, Logging drosseln, Tamper-Protection umgehen [4].
- **T1566 – Phishing** als Eingang, **T1059 – Command and Scripting Interpreter** als Ausführungsprimativ (heute seltener PowerShell als bei früheren Generationen) [20].

### Procedure-Beispiele direkt aus T1486

- **Akira** verschlüsselt mit **ChaCha20 und ChaCha8** Stream-Ciphers [2].
- T1486 deckt ausdrücklich auch ESXi- und Cloud-Objekte ab; der Technique-Text nennt Hypervisor-Jackpotting und S3-Ransomware über SSE-C als beobachtete Varianten [2].

## 3. Was in EDR/AV-Umgebungen 2025/26 noch trägt

**Verbrannt:** Custom-Packer, Base64-/XOR-Obfuskation, PowerShell-AMSI-Bypässe per Reflection, VBA-Makros im Enterprise-Kontext, Metasploit-/Cobalt-Strike-Default-Shellcode. Moderne Produkte **emulieren Ausführung in der Sandbox**, **hooken Userland-APIs in NTDLL**, **scannen Speicherregionen periodisch**, **lesen ETW** und **nutzen Kernel-Callbacks** für Prozess-, Thread- und Image-Load-Ereignisse. Der Schwerpunkt liegt auf **Verhalten statt Dateibild** [5].

**Tragfähig:**

1. **Direct Syscalls (HellsGate/HalosGate)** – `syscall` mit korrekter SSN umgeht den Userland-Hook; Gegenmaßnahme der EDR ist das Erkennen von Syscall-Stubs außerhalb von ntdll, Gegen-Gegenmaßnahme ist Return-Address-Spoofing Richtung ntdll [5].
2. **NTDLL-Unhooking per Fresh Map** – saubere Kopie aus `\KnownDlls\ntdll.dll` oder von Platte, `.text` überschreiben; EDRs re-verifizieren ihre Hooks nach dem Laden meist nicht kontinuierlich. Gegenbeispiel: CrowdStrike Falcon re-hookt aus dem Kernel – deshalb nach dem Unhooking direkt Syscalls verwenden, um das Fenster zu verkürzen [5].
3. **Sleep-Obfuscation (Ekko, Foliage, Zilean)** – APC-basiert über Timer-APCs und `RtlCreateTimer` ohne `CreateThread`/`NtCreateThreadEx`; Stack während des Schlafs mit RopHook-Gadgets verkleiden; Verschlüsselung über legitimen Export `SystemFunction032` statt eigener Krypto-Routine [5].
4. **Callback-basierte Codeausführung** statt Threaderzeugung – `EnumSystemLocalesA`, `EnumDesktopsA`, `EnumTimeFormatsA`, `SetTimer`, `CreateThreadpoolWait` [5].
5. **Behavioral Legitimacy** – maliziöses Verhalten von normaler Admin-Arbeit nicht unterscheidbar zu machen gilt als die langlebigste Tarnung, weil jedes öffentlich dokumentierte Verfahren eine endliche Halbwertszeit hat [5].

**Freie Einordnung:** Für einen red-team-tauglichen Eigenbau ist die Reihenfolge der Wirksamkeit: (a) keine Kindprozesse erzeugen, (b) Schreibrate und Dateizugriffsmuster menschlich machen, (c) Transport ununterscheidbar machen, (d) erst danach Syscall-Hygiene. Die aufwendigsten Maßnahmen bringen am wenigsten, wenn (a) und (b) falsch sind.

## 4. Detektion – die Signale, die tatsächlich funktionieren

- **Verhaltenssignaturen:** Eine legitime Anwendung liest selten Hunderte Dateien in rascher Folge, schreibt verschlüsselte Fassungen zurück und löscht Originale binnen Sekunden. Beobachtet werden **High-Entropy-Writes**, **Rename-Bursts** (angehängte Extension) und Schreib-/Leserate [6].
- **Canary-/Tripwire-Dateien:** platzierte Köder-Dateien plus SACL-Auditierung oder FSRM; jede Berührung wird zum automatischen Containment-Trigger [7].
- **VSS-/Snapshot-Tampering als Frühwarn:** Schattenkopie-Löschung ist die Aktion, mit der Ransomware sich verrät, *bevor* Schaden entsteht. Defensive Basis: Systemschutz aktiviert mit sinnvollem Shadow-Speicher, **Command-Line-Prozess-Audit** eingeschaltet, Alarm auf die kleine feste Menge an Löschkommandos [8].
- **Backup-Seite überwachen:** Kompromittierte Backups verschlechtern das Ergebnis messbar – Backup-Infrastruktur ist Teil der Angriffsfläche, nicht des Schutzwalls [9].
- **Netzseite:** Exfiltrationsvolumen, untypische Egress-Ziele, JA3/JA4-Fingerabdrücke, Beacon-Jitter-Anomalien (freies Fachwissen).
- **KI-gestützte Detektion** wird breit beworben; die belastbare Aussage ist, dass moderne Scan-Engines Verhaltensmuster lernen – nicht, dass sie damit unbekannte Familien sicher finden [10].

## 5. Detektions- vs. Evasions-Rüstungswettlauf

Jede öffentlich dokumentierte Evasion-Technik hat eine **endliche Lebensdauer**; das Ziel ist nicht der magische Bypass, sondern das Verständnis der Detektionsprinzipien auf Kernel-Ebene (Treiber, ETW-Provider), um sich anpassen zu können [5]. Verteidigungsseitig heißt das: **Verhalten, Identität und Datenabfluss** sind die drei stabilen Messgrößen; Binär-Obfuskation ist es nicht.

## Quellen

- [1] Picus Security – The Ransomware Attack Lifecycle from the Defender's Perspective: https://www.picussecurity.com/resource/the-ransomware-attack-lifecycle-from-the-defenders-perspective
- [2] MITRE ATT&CK T1486 Data Encrypted for Impact (v20): https://attack.mitre.org/techniques/T1486/
- [3] T1490 Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- [4] Picus Security – Detection and Prevention in the Late Phase (T1562): https://www.picussecurity.com/resource/detection-and-prevention-in-the-late-phase-of-the-ransomware-attacks
- [5] VulnQuest – EDR Evasion in 2025: What Still Works and Why: https://vulnquest58.github.io/redteam/research/edr-evasion-2025/
- [6] Adaptive Security – Ransomware Detection: https://www.adaptivesecurity.com/blog/ransomware-detection
- [7] Mjolnir Security – Detecting Ransomware with Canary Files and Tripwires: https://intel.mjolnirsecurity.com/detect-canary-files.html
- [8] WinSentinel – Auditing VSS Shadow Copy Tampering: https://winsentinel.ai/blog/auditing-vss-shadow-copy-tampering
- [9] Sophos – Kompromittierte Backups bei Ransomware-Angriffen: https://www.sophos.com/de-de/resources/impact-compromised-backups-ransomware-outcomes
- [10] Deutschlandfunk – KI schützt vor Viren und Ransomware: https://www.deutschlandfunk.de/ki-cybersecurity-hackerangriffe-computerviren-sicherheit-100.html
- [20] CyberQuizzer – MITRE ATT&CK Cheat Sheet: https://www.cyberquizzer.com/cheat-sheets/mitre-attack-enterprise-matrix
