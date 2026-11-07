# Ransomware – Band 16: Active-Directory-Intrusion und Domänen-Deployment

Programmiertechnischer und architektonischer Band: Kerberos-Missbrauch, AD CS ESC-Angriffe, GPO/MECM-Ausrollung und Kernel-EDR-Blinding (BYOVD). Quellen am Ende.

## 1. Die Pre-Ransomware-Phase: Vom Foothold zur Domänenkontrolle

Eine Ransomware-Payload wird im Unternehmensnetzwerk praktisch nie isoliert auf einem einzelnen Arbeitsplatz gestartet. Ihr zerstörerischer Hebel entsteht durch die **netzwerkweite, gleichzeitige Detonation** auf allen Domänen-Endpunkten und Servern. Die Phase zwischen initialem Zugriff (Initial Access) und Ausrollung der Verschlüsselung (Dwell Time) sank laut Incident-Response-Berichten von Wochen auf unter 24 Stunden (Median 2025/2026).

### 1.1 Kerberoasting (T1558.003)
Zielt auf Dienstkonten (Service Accounts) mit gesetzten Service Principal Names (SPNs).
- **Mechanik:** Jeder authentifizierte Domänenbenutzer kann für jeden beliebigen SPN ein Kerberos Ticket Granting Service (TGS)-Ticket beim Key Distribution Center (KDC) anfordern (`TGS-REQ`).
- **Schwachstelle:** Das Ticket ist mit dem NTLM- oder AES-Schlüssel des Ziel-Dienstkontos verschlüsselt. Der Angreifer extrahiert das Ticket aus dem Speicher oder Netzwerkstream und bricht es offline.
- **Angriffstool:** `GetUserSPNs.py` (Impacket) oder `Rubeus`:
  ```powershell
  Rubeus.exe kerberoast /outfile:hashes.kerberoast
  ```
- **Cracking:** Hashcat Mode 13100 (RC4-HMAC) oder Mode 19600/19700 (AES128/AES256):
  ```bash
  hashcat -m 13100 -a 0 hashes.kerberoast wordlist.txt
  ```
- **Impact:** Viele Dienstkonten (z. B. für SQL Server, Backup-Software oder Monitoring) besitzen lokale Administratorrechte auf Hunderten Servern oder sind Mitglieder privilegierter Domänengruppen.

### 1.2 AS-REP Roasting (T1558.004)
- Zielt auf Konten, bei denen die Kerberos-Vorauthentifizierung (`DONT_REQ_PREAUTH`) deaktiviert ist.
- Der Angreifer sendet ein `AS-REQ` für das Konto ohne Authentifizierung; das KDC antwortet mit einem `AS-REP`, dessen verschlüsselter Teil das Passwort des Kontos enthält.
- Offline-Cracking mit Hashcat Mode 18200.

### 1.3 BloodHound-Graphenanalyse
Angreifer verwenden BloodHound / SharpHound zur Abfrage von LDAP, Session-Daten und ACLs:
- Identifikation von ACL-Fehlkonfigurationen: `GenericAll`, `WriteDacl`, `AllExtendedRights`, `ForceChangePassword`.
- Auffinden des kürzesten Pfades (Shortest Path) zur Gruppe `Domain Admins` oder zu Domänen-Controllern.

---

## 2. Active Directory Certificate Services (AD CS) Exploitation

Active Directory Certificate Services (AD CS) ist seit der Veröffentlichung der "Certified Pre-Owned"-Forschung von SpecterOps der bevorzugte Vektor für sofortige, unbemerkte Privilegien-Eskalation zur Domänen-Übernahme.

### 2.1 ESC1: SAN-Spezifikation bei Client Authentication
- **Bedingung:** Ein Zertifikatstemplate erlaubt Client Authentication (`id-kp-clientAuth`), gewährt Domänenbenutzern das Recht zur Zertifikatanforderung (`Enroll`) und besitzt das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`ENROLLEE_SUPPLIES_SUBJECT = True`).
- **Angriff:** Ein einfacher Standardbenutzer fordert ein Zertifikat an und spezifiziert im Subject Alternative Name (SAN) den User Principal Name (UPN) des Domänen-Administrators:
  ```bash
  certipy req -u user@domain.local -p password -ca DOMAIN-CA -template VulnerableTemplate -upn Administrator@domain.local
  ```
- **Eskalation:** Das ausgestellte Zertifikat wird via PKINIT (Public Key Cryptography for Initial Authentication) gegen das KDC eingelöst, um ein vollwertiges Ticket Granting Ticket (TGT) des Domänen-Administrators zu erhalten:
  ```bash
  certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
  ```

### 2.2 ESC8: NTLM Relay auf HTTP Web Enrollment
- AD CS installiert oft unsichere HTTP-Endpunkte für Web Enrollment (z. B. `http://<ca>/certsrv/`), die keine NTLM-Signatur (EPA - Extended Protection for Authentication) erzwingen.
- **Coerced Authentication:** Angreifer erzwingen eine NTLM-Authentifizierung eines Domänen-Controllers über MS-EFSR (PetitPotam) oder MS-RPRN (PrinterBug):
  ```bash
  python3 PetitPotam.py <relay-ip> <dc-ip>
  ```
- **Relay:** Der NTLM-Verbindungsaufbau des DCs wird via `ntlmrelayx` an den Web-Enrollment-Endpunkt der CA weitergeleitet:
  ```bash
  ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController
  ```
- **Ergebnis:** Die CA stellt ein gültiges Rechnerzertifikat für den Domain Controller aus. Der Angreifer erhält das Zertifikat, fordert ein TGT für den DC an und führt einen **DCSync** durch (`secretsdump.py`), womit alle NTLM-Hashes der Domäne (inklusive `krbtgt`) entwendet sind.

---

## 3. Domänenweites Ausrollen der Ransomware-Payload

Sobald Domänen-Admin-Rechte vorliegen, erfolgt die softwaregestützte Verteilung des Ransomware-Implantats auf Tausende Zielsysteme.

### 3.1 GPO (Group Policy Object) Push
Der effektivste und am häufigsten beobachtete Verteilungsmechanismus für Ransomware (z. B. LockBit, BlackCat):
1. **GPO anlegen und verlinken:**
   - Erstellen einer neuen Gruppenrichtlinie und Verknüpfen mit der Root-OU der Domäne (wirksam auf alle Workstations und Server).
2. **Sofortige Aufgabenplanung (Immediate Scheduled Task):**
   - Einbettung eines Scheduled Tasks in die GPO via `SYSVOL/Policies/{GUID}/User/Preferences/ScheduledTasks/ScheduledTasks.xml`.
   - Die Aufgabe läuft unter dem Benutzerkonto `NT AUTHORITY\SYSTEM`.
   - Payload-Ablage: Die Binärdatei wird in `SYSVOL` oder einer offenen administrativen Freigabe abgelegt (`\\domain.local\sysvol\domain.local\scripts\payload.exe`).
3. **Forcierung der Ausführung:**
   - Warten auf das GPO-Aktualisierungsintervall (90 Minuten) oder aktives Pushen via `gpupdate /force` über WMI/PowerShell.

### 3.2 MECM / SCCM Missbrauch
In großen Enterprise-Netzen nutzen Angreifer vorhandene Software-Management-Systeme (Microsoft Endpoint Configuration Manager):
- Erstellen eines neuen Software-Deployments mit hoher Priorität.
- Die MECM-Client-Agenten auf allen Endpoints führen die Ransomware zeitgesteuert und synchron mit höchsten Rechten aus.

### 3.3 Parallele Admin-Shares & WinRM / WMI
- **PsExec / PaExec:** `psexec.exe @targets.txt -u DOMAIN\Admin -p Pass -c -d -s payload.exe`
- **WMI / CIM:** `wmic /node:@hosts.txt process call create "cmd.exe /c start \\share\payload.exe"`
- **PowerShell Remoting (WinRM):** `Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock { Start-Process C:\Windows\Temp\enc.exe }`

---

## 4. EDR Blinding via BYOVD (Bring Your Own Vulnerable Driver)

Moderne Endgeräte sind mit EDR-Lösungen (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) geschützt. EDR-Agenten laufen als geschützte Prozesse (`PsProtectedProcessLight` PPL) und binden Kernel-Treiber mit Early Launch Anti-Malware (ELAM) ein. Ein Benutzerprozess – selbst als `SYSTEM` – kann den EDR-Dienst nicht terminieren (`Access Denied`).

### Das BYOVD-Konzept (T1068, T1562.001)
Um den Kernel-Schutz zu brechen, nutzen Angreifer legitim von Microsoft oder Drittanbietern signierte Treiber, die bekannte Schwachstellen (beliebige Lese- und Schreibzugriffe auf den Kernel-Speicher) enthalten.
- **Voraussetzung:** Lokale Administratorrechte mit `SeLoadDriverPrivilege`.
- **Bekannte verwundbare Treiber:**
  - `gdrv.sys` (Gigabyte, CVE-2018-19320)
  - `mhyprot2.sys` (Genshin Impact Anti-Cheat Treiber)
  - `procexp.sys` (Process Explorer älterer Versionen)
  - `DBUtil_2_3.sys` (Dell Firmware Update Utility)

### Kernel-Manipulation im Speicher
Sobald der Treiber geladen ist, sendet das Implantat IOCTLs (Input/Output Control), um Kernel-Strukturen gezielt zu überschreiben:

1. **Kernel Callbacks neutralisieren:**
   - Windows-Kernel registriert Callbacks für Überwachungstools:
     - `PspCreateProcessNotifyRoutine` (Meldet Prozessstarts)
     - `PspCreateThreadNotifyRoutine` (Meldet Thread-Erzeugungen)
     - `PspCreateImageNotifyRoutine` (Meldet DLL-/Treiber-Ladevorgänge)
   - Das BYOVD-Implantat traversiert das Callback-Array im Kernel und nullt die Funktionspointer der EDR-Treiber aus.
2. **Object Callbacks manipulieren:**
   - `ObRegisterCallbacks` schützt EDR-Prozesse vor `OpenProcess(PROCESS_TERMINATE)`. Durch Löschen der Callback-Einträge wird der Prozessschutz aufgehoben.
3. **EDR-Status:**
   - Der EDR-Dienst läuft weiter und sendet Herzschläge an das Cloud-Dashboard.
   - Der EDR ist jedoch vollkommen blind: Weder Dateiverschlüsselung, Hooking noch Speichermanipulationen erzeugen Warnmeldungen.

---

## 5. Detektion und Abwehr (Gegenprobe)

### Active Directory Audit & Telemetrie
1. **Kerberos-Anomalien:**
   - **Event ID 4768 / 4769:** Häufung von TGS-Anforderungen mit Verschlüsselungstyp `0x17` (RC4-HMAC) für Dienstkonten signalisiert Kerberoasting.
   - Überwachung von TGS-Anfragen von unüblichen Quell-IPs oder massenhaft innerhalb weniger Sekunden.
2. **AD CS Monitoring:**
   - **Event ID 4886 / 4887:** Zertifikatanforderung und -ausstellung auf der Zertifizierungsstelle.
   - Alarmierung bei Zertifikatanforderungen mit gesetztem SAN für privilegierte Konten (`Administrator`, `krbtgt`).

### Schutz gegen BYOVD
1. **HVCI (Hypervisor-Protected Code Integrity) / Memory Integrity:**
   - Nutzt hardwaregestützte Virtualisierung, um sicherzustellen, dass nur signierter und verifizierter Code im Kernel ausgeführt wird.
2. **Microsoft Vulnerable Driver Blocklist:**
   - Blockiert das Laden bekannter verwundbarer Treiber (wie `gdrv.sys` und `mhyprot2.sys`) per Richtlinie.
3. **AppLocker / WDAC (Windows Defender Application Control):**
   - Striktes Whitelisting von Treibern und Skripten.

### Architektur-Härtung (Enterprise Access Model)
- **Keine Domain-Admin-Logins auf Tier-1 (Server) oder Tier-2 (Clients):**
  - Verhindert das Auslesen von Domain-Admin-Hashes aus LSASS auf kompromittierten Systemen.
- **Dedicated PAM / Jump Hosts:**
  - Administrative Zugriffe ausschließlich über gehärtete Privilege Access Workstations (PAWs).

---

## Quellen

- SpecterOps: Certified Pre-Owned – Can You Have a Second Certificate? (AD CS Research, 2021).
- SpecterOps: BloodHound Active Directory Graph Theory & Attack Paths.
- Microsoft Learn: Kerberos Authentication Architecture & Event ID 4769 Reference.
- Trend Micro: Bring Your Own Vulnerable Driver (BYOVD) Attacks in Ransomware Operations (2024/2025).
- BSI: Kompendium Videokonferenz- und Verzeichnisdienste – Gefährdungslage Active Directory.
- MITRE ATT&CK: T1558 (Steal or Forge Kerberos Tickets), T1068 (Exploitation for Privilege Escalation), T1562.001 (Impair Defenses: Disable or Modify Tools).
