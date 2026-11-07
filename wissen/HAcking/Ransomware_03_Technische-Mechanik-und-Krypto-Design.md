# Ransomware – Band 3: Technische Mechanik und Krypto-Design

Stand August 2026. Belegtes ist referenziert, Designerisches aus eigener Fachkenntnis ist als Einordnung gekennzeichnet.

## 1. Bauformen

| Bauform | Was passiert | typischer Schaden |
|---|---|---|
| **Crypto-Ransomware** | Einzeldateien werden verschlüsselt, Daten bleiben auf dem Datenträger | Availability + (bei Exfiltration) Confidentiality [1] |
| **Locker** | UI/OS gesperrt (Kiosk-Umgehung, RDP-Hijack), Dateien bleiben lesbar | nur Availability, meist Consumer [1] |
| **Full-Disk / Bootkit** | MBR/Boot-Sektor oder ganzer Volume verschlüsselt, Ransom-Note vor OS-Start | Systemkomplettausfall |
| **Wiper im Ransomware-Mantel** | Verschlüsseln/Überschreiben ohne Recovery-Pfad (NotPetya: MBR + MFT) | Totalverlust, kein Zahlungshebel [1] |
| **Hypervisor-Locker** | ESXi/Vsphere-Host verschlüsselt VMs en bloc | Multi-Tenant-Ausfall [14][15] |
| **Cloud-/IaaS-Variante** | Storage-Objekte via natives Verschlüsselungsfeature verschlüsselt (AWS SSE-C) | Flächenbrand pro Account [5] |

## 2. Krypto-Architektur – vom schwachen zum tragfähigen Design

### Historische Stufen

1. **Symmetrisch, Schlüssel lokal in der Binary** – AIDS Trojan, frühe GpCode. Analysten bauen Decryptor, Zahlung unnötig [1].
2. **RSA mit fest eingebettetem Public Key** – GpCode-Spätvarianten (1024 Bit), Archiveus (2006), CryptoLocker (2048 Bit). Privater Schlüssel nur beim Betreiber [1].
3. **RSA + AES-Hybrid (Key-Wrapping)** – Standard seit Mitte 2010er: pro Datei/Host zufällige AES-DEK, DEK mit RSA des Betreibers umschlossen, nur Wraps verlassen das System. Effizienz einer Blockchiffre plus Public-Key-Custody.
4. **Heute: Hybrid KEM/AEAD post-quantum-fähig** – X25519 + ML-KEM-768 (NIST FIPS 203) für Key Establishment, AEAD für Daten, Argon2id/HKDF für Ableitung. Gruppen setzen real ChaCha20/ChaCha8 (Akira) oder AES-Varianten ein [5].

### Referenzdesign für eine Neuentwicklung (freies Fachwissen)

- **Trust-Regel:** Der Master-Key darf die Operator-Seite nie verlassen; das Opfer-System kennt nur ephemere Schlüssel.
- **Pro Host:** ephemere X25519- und ML-KEM-768-Keys, gemeinsames Secret über HKDF → Host-Master.
- **Pro Datei:** zufällige DEK, AEAD (AES-256-GCM oder ChaCha20-Poly1305), Nonce-Disziplin ohne Wiederverwendung.
- **Rückgabe:** nur gewrappte DEKs an den Server; dort Verschlüsselung unter Operator-Master.
- **Wichtig:** RSA ist nicht per se unsicher – RSA-2048 bleibt brauchbar –, aber ein auf der Platte liegender Key-Container ist der häufigste Realitätsfehler, nicht die Algorithmuswahl.

### Teilverschlüsselung (Partial Encryption) – warum sie Standard ist

- Nur Dateikopf/-fuß (z. B. erste und letzte 1 MB) zu verschlüsseln senkt die Laufzeit um Größenordnungen und genügt, um office-taugliche Dateien unbrauchbar zu machen.
- Konsequenz: **Große Datenbanken, VHDX und Images werden trotzdem getroffen** – Entropy-/Größenschwellen müssen definiert sein.
- Freie Einordnung: Für einen Schulungs-/Red-Team-Nachbau ist Partial-Encryption der Hebel, der den Unterschied zwischen "brennt 40 Minuten" und "brennt 4 Stunden" markiert.

## 3. Dateioperation und Nebenwirkungen

- **Umbenennen mit Extension** (`.lockbit`, `.akira`, zufällige 16-Zeichen-Ketten) ist ein Nebeneffekt, aber auch das stärkste Detektionsmerkmal: Rename-Bursts und hohe Entropie-Schreibraten sind das klassische Verhaltenssignal von Detektionswerkzeugen [16].
- **Manifest-Dateien** pro Verzeichnis erlauben einen linearen, idempotenten Entschlüsselungslauf – Vorbedingung für Recovery ohne Chaos.
- **Absturz mitten im Lauf:** ohne Journaling/Resume-Log entsteht Datenkorruption statt Verschlüsselung; Idempotenz ist Designpflicht, nicht Kür.
- **Ausschlusslisten** sind sicherheitskritisch: Windows-, Programm-, Boot-/EFI-Pfade, Pagefile/Hiberfil, eigene Binary, USB-Bootmedien, freigegebene Spool- und Cluster-Verzeichnisse.

## 4. Recovery-Zerstörung (MITRE T1490, Inhibit System Recovery)

| Methode | Lautstärke | Bemerkung |
|---|---|---|
| `vssadmin delete shadows /all /quiet` | laut | eigener Kindprozess, Audit-Alarm, Signaturfall [17] |
| `wmic shadowcopy delete` | laut | auf neueren Systemen Deprecated, fällt oft still durch |
| **DeviceIoControl / VSS-API direkt** | **leise** | kein Kindprozess, kein Command-Line-Audit – von Sodinokibi populär gemacht [17] |
| VSS-Dienst deaktivieren / Snapshot-Speicher auf 0 setzen | mittel | verhindert neue Snapshots |
| Backup-Kataloge löschen (`wbadmin delete systemstatebackup`, Catalogdb) | mittel | wird von modernen Familien mitgemacht |
| ReFS-/ZFS-Snapshots, Btrfs-Snapshots, NetApp-/Synology-Snapshots | OS-abhängig | Linux/Storage-Arrays werden zunehmend mitgenommen |

**Freie Einordnung:** Genau hier trennt sich gute von naiver Ransomware. Der Weg über `DeviceIoControl` statt über Kindprozesse ist der praktischste Einzelgewinn an Leise – ohne Syscall-Akrobatik.

## 5. Persistence und Startverhalten

- Autostart-Registry-Keys (`Run`, `RunOnce`), geplanter Task, Dienst, Startup-Ordner; bei Bootkit-Varianten MBR- oder EFI-Bootsegment.
- Start **vor** Benutzerlogin ist nötig, um auch geschlossene Dateien und Netzlaufwerke im Logon-Kontext zu erwischen.
- **Keine Selbstlöschung erzwingen:** sie zerstört Forensik und erhöht im Schulungskontext nur das Chaos.

## 6. Anti-Recovery und psychologische Druckmittel

- Ransom-Note in mehreren Sprachen auf jedem Verzeichnis + Desktop-Hintergrund (MITRE Internal Defacement, T1491.001) [5].
- **"Print Bombing"**: Ransom-Noten auf verbundene Drucker ausgeben – als Druckmittel dokumentiert [5].
- Tor-/I2P-Chatportal für Verhandlung; Countdown mit Preiserhöhung; Leak-Site-Showcase.

## 7. Plattformverlagerung: ESXi, Linux, Cloud

- **Hypervisor Jackpotting**: ESXi-Hosts werden gezielt verschlüsselt, weil ein Host viele VMs auf einmal legt. CrowdStrike beschreibt die Technique seit 2021 und die Anfälligkeit u. a. wegen fehlender Security-Tools auf ESXi [14][15].
- **2025-Realität:** Huntress-Case-Daten zeigen, dass der Anteil des Hypervisors an bösartiger Verschlüsselung von 3 % in H1 2025 auf 25 % im zweiten Halbjahr 2025 gesprungen ist [18].
- **Babuk-Leak-Effekt:** Leaked Source erzeugt Familien. SentinelLABS zählte zehn Ransomware-Familien mit ESXi-Lockern auf Babuk-Basis [19].
- **ESXi-Schwachstelle für Massenverschlüsselung:** Microsoft beobachtete 2024 Ausnutzung einer ESXi-Lücke für vollen Admin-Zugriff auf domain-joined Hosts [20].
- **Persistence auf ESXi über SSH-Tunneling** – Hosts werden nicht nur verschlüsselt, sondern als Rückkanal missbraucht [21].
- **Cloud:** Storage-Objekte kompromittierter Accounts; AWS **SSE-C** wird als natives Verschlüsselungswerkzeug gegen den Opfer-Account selbst missbraucht [5].
- **Freie Einordnung:** Der Mangel an Agenten auf Hypervisoren und IaaS-Steuerungsebenen ist strukturell – dieselbe Lücke, die 2017 WannaCry brauchte (kein Endpoint-Schutz), existiert heute auf ESXi und in Cloud-APIs.

## Quellen

- [1] CyberDefenders – History of Ransomware: https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/
- [5] MITRE ATT&CK T1486 Data Encrypted for Impact (v20, Stand 12.05.2026): https://attack.mitre.org/techniques/T1486/
- [14] CrowdStrike – Hypervisor Jackpotting, Part 2: https://www.crowdstrike.com/en-us/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
- [15] Huntress – Hardening the Hypervisor: https://www.huntress.com/blog/hypervisor-defenses-against-ransomware-targeting-esxi
- [16] Adaptive Security – Ransomware Detection: https://www.adaptivesecurity.com/blog/ransomware-detection
- [17] Picus Security – An Underrated Technique to Delete Volume Shadow Copies: https://www.picussecurity.com/resource/blog/technique-to-delete-volume-shadow-copies-deviceiocontrol · VMware Security – Illuminating Volume Shadow Deletion: https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html
- [18] Huntress-Case-Daten via https://www.huntress.com/blog/hypervisor-defenses-against-ransomware-targeting-esxi
- [19] SentinelOne Labs – Hypervisor Ransomware / Babuk: https://www.sentinelone.com/labs/hypervisor-ransomware-multiple-threat-actor-groups-hop-on-leaked-babuk-code-to-build-esxi-lockers/
- [20] Microsoft – Ransomware operators exploit ESXi hypervisor vulnerability: https://www.microsoft.com/en-us/security/blog/2024-07-29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/
- [21] Sygnia – ESXi Ransomware Attacks: Stealthy Persistence through SSH Tunneling: https://www.sygnia.co/blog/esxi-ransomware-ssh-tunneling-defense-strategies/
