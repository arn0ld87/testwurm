# Ransomware – Wissenssammlung

Mehrteilige Wissensbasis, aufgebaut im August 2026 und umfassend erweitert im November 2026 auf Basis aktueller Quellen: Check Point Research (Q3 2025), Coveware (Q3 2025), MITRE ATT&CK v20, CyberDefenders, NCA/Europol, Huntress, Sophos, BSI-Empfehlungen, NIST FIPS 203/204, SpecterOps, CISA, Mandiant und internationale Fachliteratur. Jede Notiz trennt **belegte Aussagen** (Quellenliste am Ende) von **freier fachlicher Einordnung**, die ausdrücklich als solche gekennzeichnet ist.

## Bänder

| Band | Thema | Inhalt in Kürze |
|---|---|---|
| **00** | Diese Übersicht | Register, 26 Kernsätze, Querverweise und Zielgruppen-Lesepfade |
| **01** | Historie und Entwicklungslinien | AIDS Trojan 1989 bis RaaS; fünf Epochen und ihr jeweiliger Verteidigungszwang |
| **02** | Angriffsökonomie, RaaS und Bedingungslage | Fallzahlen Q3 2025, Fragmentierung, Operation Cronos, Erpressungsmodelle, Zahlungsquoten, Initial Access |
| **03** | Technische Mechanik und Krypto-Design | Bauformen, Krypto-Architektur, Partial Encryption, Recovery-Zerstörung, Persistence, ESXi/Linux/Cloud |
| **04** | Kill Chain, MITRE ATT&CK, Evasion und Detektion | Phasenmodell, Technik-IDs, EDR-Evasion 2025/26, Canary-Files, Verhaltensdetektion |
| **05** | Abwehr, Incident Response und Rechtslage | 3-2-1-1-0, Immutable Backups, Härtung, IR-Ablauf, Verhandeln, Rechtslage Deutschland, NIS2/DSGVO |
| **06** | Meilensteine, Akteure und Einzelfälle | WannaCry, NotPetya, Maze, Colonial Pipeline, Kaseya, LockBit, Change Healthcare – und was sie geändert haben |
| **07** | Quellen, Methodik, offene Punkte | Vollständiges Quellenverzeichnis (Q1–Q92), Belastbarkeitsstufen, Abdeckungsmatrix, Ausbaustatus |
| **08** | Windows-API in der Implementierung | Prozess-/Dienstjagd, Privilegketten, Volume-Handling, Enumeration, IOCP, Partial-Encryption-Parameter, Fehlermatrix, Lock-only-Angriff |
| **09** | Krypto-Implementierung und Datenformate | Bibliothekswahl, BCrypt-Fallstricke, Nonce-/Key-Hygiene, Chunk-Formate, Header-Felder, Decryptor-Pflichten |
| **10** | Sprachwahl, Build-Hygiene, Evasion-Code | C++/Rust/Go anhand realer Befunde, PE-Hygiene, String-/API-Obfuskation, ETW, Prozessmodell |
| **11** | C2 und Steuerungsapp technisch | Beacon-Loop, Jitter, Task-Invarianten, mTLS, Transport-OPSEC, Server-Schema, Rollen |
| **12** | Testharness, Messgrößen, Gegenprobe | Goldene Dateien, Crash-Roundtrip, Durchsatzmessung, eigene Detektionsgegenprobe, Abnahmekriterien |
| **13** | Pflichtenheft Teil 1 – Architektur & Anforderungen | Systemarchitektur, Datenmodelle, funktionale und nichtfunktionale Spezifikation |
| **14** | Pflichtenheft Teil 2 – Meilensteine, Risiken & Evaluation | Meilensteinplanung, Risikomatrix, Testkriterien und Abnahme |
| **15** | Linux- und ESXi-Implementierungspfad (POSIX-Mechanik) | VMkernel-Eigenheiten, `vim-cmd` Shutdown, VMFS-Locks, `O_DIRECT`/`pwrite64`, Babuk/LockBit ESXi, eBPF-Gegenprobe |
| **16** | Active-Directory-Intrusion und Domänen-Deployment | Kerberoasting, AS-REP Roasting, AD CS ESC1/ESC8 Missbrauch, GPO/MECM-Push, EDR-Blinding via BYOVD |
| **17** | Cloud- und SaaS-Ransomware (Multi-Tier-Extortion) | AWS S3 SSE-C Attacken, KMS Key Swap & Deletion, Entra ID PrivEsc, 4-Stufen-Erpressung (DDoS, Harassment, SEC/DSGVO) |
| **18** | Post-Quantum-Kryptographie und Hybride KEM | NIST FIPS 203 (ML-KEM-768 / Kyber) + FIPS 204 (ML-DSA), Hybrid-KEM mit X25519, Header-Overhead und Directory-Sharing |
| **19** | Krypto-Forensik, Key-Recovery und Decryptor-Bau | RAM-Forensik mit Volatility/aeskeyfind, Reale Krypto-Fehler (PRNG, Nonce-Reuse), No More Ransom Decryptor-Design |
| **20** | EDR-Hook-Evasion und Loader-Architektur | User-Mode Hooking in `ntdll.dll`, Direct & Indirect Syscalls (Hell's/Halo's Gate), Stack Spoofing, AMSI/ETW-Patching |
| **21** | C2-Infrastruktur und Exfiltrations-Pipelines | Multi-Tier C2 (Redirectors, CDN Fronting), Malleable Profiles, JA4-Spoofing, DNS-Tunneling, Rclone Pre-Encryption Exfiltration |
| **22** | OT-, ICS- und SCADA-Targeting | Purdue-Modell-Traversierung, EKANS/Snake Dienst-Killen (WinCC, FactoryTalk, Proficy), Modbus/CIP-Missbrauch, SIS-Bedrohung |
| **23** | Anti-Forensik, MFT-Manipulation und Log-Neutralisierung | NTFS `$UsnJrnl` & `$LogFile` Löschung, Timestomping ($STANDARD_INFO vs $FILE_NAME), In-Memory EventLog Thread Suspension |
| **24** | Enterprise-Storage- und SAN/NAS-API-Targeting | Storage-Array REST APIs (NetApp, Pure Storage, Dell), Snapshot-Vernichtung, DBMS-Targeting (.mdf/.ldf), WORM/SafeMode |
| **25** | Kubernetes- und Cloud-Native-Ransomware | K8s Cluster Intrusion, ServiceAccount-Missbrauch, etcd-Dump, bösartige DaemonSets, CSI PersistentVolume Sabotage |
| **26** | Wiper-Mechanik vs. Ransomware (Destruktive Payloads) | NotPetya, WhisperGate, HermeticWiper Dekonstruktion; MBR/GPT-Zeroing, MFT-Cluster-Zerstörung, mathematischer Beweis der Fake-Krypto |
| **27** | Kali Linux – Werkzeug-Ökosystem und Tool-Chaining | PTES-Methodik, Recon (`nmap`, `masscan`), Web (`burp`, `sqlmap`), AD (`impacket`, `netexec`, `bloodhound`), Cracking (`hashcat`) |

## Die 26 Kernsätze der Sammlung

1. Das Erpressungsmodell ist seit 1989 unverändert; was sich änderte, waren die Randbedingungen [Band 01].
2. Wirksam wurde Ransomware erst durch das Zusammentreffen von starker Krypto, anonymem Geld und mietbarer Fähigkeit [Band 01].
3. Doppelte Erpressung hat Backup als alleinige Antwort entwertet [Band 01, 02].
4. Takedowns von Top-Marken senken das Gesamtvolumen nicht, weil Affiliates abwandern [Band 02, 06].
5. Die Zahlungsrate sinkt historisch – 23 % in Q3 2025 –, Verweigerung wird zur Mehrheitsstrategie [Band 02].
6. Initiale Intrusion läuft immer häufiger über gestohlene Identitäten statt über Exploits [Band 02].
7. Detektion passiert über Verhalten, nicht über Dateibild; Packer- und Encoding-Tricks sind verbraucht [Band 04].
8. Recovery-Zerstörung ist das leise Vorzeichen der Verschlüsselung und der beste Frühwarnanker [Band 03, 04].
9. Backup-Infrastruktur ist Teil der Angriffsfläche, nicht des Schutzwalls [Band 05].
10. Resilienz und Exfiltrationskontrolle sind die einzigen Hebel, die gegen RaaS strukturell wirken [Band 02, 05].
11. Krypto-Design schlägt Algorithmuswahl: die meisten Eigenbaufehler stecken in Nonce-Führung, Chunk-Format und Marker-Randfällen, nicht in der Primitive-Wahl [Band 09].
12. Ein Schlüssel, der nicht vor der ersten Datenmutation beim Server angekommen ist, kann den gesamten Vorfall unnachspielbar machen [Band 11].
13. Locking ohne Schreiben ist eine vollständige Angriffsvariante, gegen die Canary-Files und Write-Rate-Detektion wirkungslos bleiben [Band 08, 12].
14. Hypervisoren sind der größte Schadenshebel: Ein kompromittierter ESXi-Host verschlüsselt hunderte Server gleichzeitig auf Block-Ebene [Band 15].
15. Active Directory ist die Ausroll-Infrastruktur: Ohne Domänenübernahme und Zertifikatsmissbrauch (AD CS) skaliert Ransomware im Unternehmensnetz nicht [Band 16].
16. In der Cloud verschlüsselt der Angreifer nicht Festplatten, sondern entzieht die Schlüsselverwaltung (SSE-C, KMS-Swap) [Band 17].
17. Post-Quantum-Krypto ist im Ransomware-Design angekommen: Hybride KEM schützt Angreifer vor künftigen Quantencomputern [Band 18].
18. Jede erfolgreiche Entschlüsselung ohne Zahlung beruht auf flüchtigem RAM, Implementierungsfehlern oder beschlagnahmter Infrastruktur [Band 19].
19. User-Mode Hooking ist ein löchriger Schutzschild: EDR-Hooks in `ntdll.dll` lassen sich über Indirect Syscalls und Synthetic Stack Spoofing umgehen [Band 20].
20. Exfiltration schlägt Verschlüsselung: Vor dem ersten verschlüsselten Block fließen Unternehmensdaten gedrosselt und gechankt über getarnte C2-Pipelines ab [Band 21].
21. OT-Ransomware greift Prozesse an, nicht Dateien: Das Terminieren von WinCC, FactoryTalk oder Experion erzwingt physikalische Produktions-Nothalte [Band 22].
22. Anti-Forensik zielt auf Metadaten: Wer `$UsnJrnl` löscht und EventLog-Threads im Speicher suspendiert, verhindert die forensische Rekonstruktion lautlos [Band 23].
23. Storage-APIs sind die Hintertür zu Backups: Wer Admin-Zugriff auf NetApp oder Pure Storage erlangt, löscht Snapshots per REST-API vor der Host-Verschlüsselung [Band 24].
24. Kubernetes skaliert Erpressung im Cluster: Bösartige DaemonSets verschlüsseln PersistentVolumes knotenübergreifend binnen Minuten [Band 25].
25. Nicht jede Ransomware will Lösegeld: Wiper wie NotPetya und HermeticWiper maskieren irreversible Sabotage hinter einer Scheinkryptographie [Band 26].
26. Methodisches Tool-Chaining in Kali Linux verbindet Einzelschritte: Professionelle Pentests und Angreifer-Workflows leben von automatisierter Datenübergabe zwischen Werkzeugen [Band 27].

## Wer sollte welchen Band lesen

- **Entscheider / Geschäftsführung:** 02 → 05 → 06 → 17 → 26
- **SOC / Blue Team:** 04 → 03 → 15 → 16 → 19 → 20 → 21 → 23 → 07
- **Red Team / Malware-Bau:** 03 → 08 → 09 → 10 → 11 → 12 → 15 → 16 → 18 → 20 → 21 → 27
- **Incident Response & Forensik:** 05 → 12 → 19 → 23 → 26
- **OT & Industrial Security Engineers:** 03 → 05 → 22
- **Storage- & Virtualisierungs-Admins:** 15 → 24
- **Cloud- & Kubernetes-Engineers:** 17 → 25
- **Recht & Compliance:** 05 → 02 → 17
- **Vorstandsvorbereitung in 15 Minuten:** nur die 26 Kernsätze oben

## Systematische Einordnung (freie Synthese)

Ransomware ist kein Malware-Problem mit Sicherheitslösung, sondern ein **ökonomischer Markt mit Angebot und Nachfrage**. Deshalb wirkt Abwehr nur entlang dreier Achsen gleichzeitig:

1. **Eintrittswahrscheinlichkeit senken** – Identität (Phishing-resistente MFA, Tiered Administration), Patching, EDR-Härtung, Segmentierung.
2. **Schadenshöhe begrenzen** – Offline-/Immutable-Backups (WORM/SafeMode/Air-Gap), getestete Restore-Ziele, Zero Trust in IT, Cloud, K8s und OT.
3. **Zahlungsanreiz neutralisieren** – Exfiltrationskontrolle, Vorbereitung auf Multi-Tier-Erpressung, dokumentierte Verhandlungs- und Meldestrategie, forensische Triage (Wiper vs. Erpressung).

Wer nur Achse 1 bedient, verliert an Achse 2 und 3 – das ist die strukturelle Lehre aus Maze bis LockBit.
