# Ransomware – Band 7: Quellen, Methodik, offene Punkte

Stand November 2026. Diese Notiz macht die Wissenssammlung überprüfbar.

## 1. Vollständiges Quellenverzeichnis

### Primär- und Fachquellen (Volltext gelesen)

| # | Quelle | URL | Verwendet in |
| --- | --- | --- | --- |
| Q1 | CyberDefenders – History of Ransomware: From Floppy Disk to RaaS (Stand 06/2026) | [https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/](https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/) | Band 01, 03, 05, 06, 22, 26 |
| Q2 | Check Point Research – The State of Ransomware, Q3 2025 (13.11.2025) | [https://research.checkpoint.com/2025/the-state-of-ransomware-q3-2025/](https://research.checkpoint.com/2025/the-state-of-ransomware-q3-2025/) | Band 02, 06, 21 |
| Q3 | MITRE ATT&CK – T1486 Data Encrypted for Impact, v20 (Last Modified 12.05.2026) | [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/) | Band 03, 04, 06 |
| Q4 | VulnQuest – EDR Evasion in 2025: What Still Works and Why | [https://vulnquest58.github.io/redteam/research/edr-evasion-2025/](https://vulnquest58.github.io/redteam/research/edr-evasion-2025/) | Band 04, 20 |
| Q5 | Coveware – Insider Threats Loom while Ransom Payment Rates Plummet (10/2025) | [https://coveware.com/2025/10/insider-threats-loom-while-ransom-payment-rates-plummet/](https://coveware.com/2025/10/insider-threats-loom-while-ransom-payment-rates-plummet/) | Band 02, 05 |
| Q6 | Huntress – Hardening the Hypervisor (ESXi-Case-Daten 2025) | [https://www.huntress.com/blog/hypervisor-defenses-against-ransomware-targeting-esxi](https://www.huntress.com/blog/hypervisor-defenses-against-ransomware-targeting-esxi) | Band 03, 05, 15 |
| Q7 | Picus Security – The Ransomware Attack Lifecycle from the Defender's Perspective | [https://www.picussecurity.com/resource/the-ransomware-attack-lifecycle-from-the-defenders-perspective](https://www.picussecurity.com/resource/the-ransomware-attack-lifecycle-from-the-defenders-perspective) | Band 04, 20, 21 |
| Q43 | Nextron Systems – In-Depth Analysis of Lynx Ransomware (11.10.2024) | [https://www.nextron-systems.com/2024-10-11/in-depth-analysis-of-lynx-ransomware/](https://www.nextron-systems.com/2024-10-11/in-depth-analysis-of-lynx-ransomware/) | Band 08, 09, 10, 12 |
| Q44 | Check Point Research – Inside Akira Ransomware's Rust Experiment (03.12.2024) | [https://research.checkpoint.com/2024/inside-akira-ransomwares-rust-experiment/](https://research.checkpoint.com/2024/inside-akira-ransomwares-rust-experiment/) | Band 10, 15 |
| Q45 | Microsoft Learn – CreateFileW (fileapi.h) | [https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) | Band 08 |
| Q46 | Microsoft Learn – BCryptEncrypt (bcrypt.h) | [https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt) | Band 09 |
| Q56 | Babuk Ransomware Source Code Leak (ESXi Module & POSIX I/O Analysis, 2021) | Leak-Archiv / vx-underground | Band 15, 19 |
| Q57 | CERT-FR – Alert on ESXiArgs Ransomware Campaign (02/2023) | [https://www.cert.ssi.gouv.fr/alerte/CERTFR-2023-ALE-015/](https://www.cert.ssi.gouv.fr/alerte/CERTFR-2023-ALE-015/) | Band 15 |
| Q58 | SpecterOps – Certified Pre-Owned: Can You Have a Second Certificate? (AD CS Research, 2021) | [https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2) | Band 16 |
| Q59 | Trend Micro – Bring Your Own Vulnerable Driver (BYOVD) Attacks in Ransomware Operations (2024/2025) | [https://www.trendmicro.com/en_us/research/24/byovd-ransomware.html](https://www.trendmicro.com/en_us/research/24/byovd-ransomware.html) | Band 16 |
| Q60 | Rhino Security Labs – S3 Ransomware: Attack Vector Using SSE-C (2023/2024) | [https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/) | Band 17, 25 |
| Q61 | AWS Security Documentation – Server-Side Encryption with Customer-Provided Keys (SSE-C) | [https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html) | Band 17 |
| Q62 | NIST – FIPS 203: Module-Lattice-based Key-Encapsulation Mechanism Standard (ML-KEM, 08/2024) | [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final) | Band 18 |
| Q63 | NIST – FIPS 204: Module-Lattice-based Digital Signature Standard (ML-DSA, 08/2024) | [https://csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final) | Band 18 |
| Q64 | Open Quantum Safe Project – liboqs Architecture & Hybrid KEM Benchmarks | [https://openquantumsafe.org/](https://openquantumsafe.org/) | Band 18 |
| Q65 | No More Ransom Initiative (Europol, Dutch National Police, Emsisoft, Kaspersky) | [https://www.nomoreransom.org/](https://www.nomoreransom.org/) | Band 19 |
| Q66 | Volatility Foundation – Volatility 3 Memory Forensics Framework & aeskeyfind | [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) | Band 19, 23 |
| Q67 | vx-underground – The Art of Syscall Bypasses: Hell's Gate, Halo's Gate & Tartarus' Gate | [https://vx-underground.org/](https://vx-underground.org/) | Band 20 |
| Q68 | Outflank – In-Depth Analysis of Direct vs. Indirect Syscalls | [https://outflank.nl/blog/](https://outflank.nl/blog/) | Band 20 |
| Q69 | Mandiant – Evading EDR with Call Stack Spoofing and Memory Scanning Bypasses | [https://www.mandiant.com/resources/blog](https://www.mandiant.com/resources/blog) | Band 20 |
| Q70 | Fox-IT – Catching the Ghost: Detecting Modern C2 Frameworks via Network Telemetry | [https://blog.fox-it.com/](https://blog.fox-it.com/) | Band 21 |
| Q71 | John Lambert – Microsoft Threat Intelligence: Defending Against Multi-Tier C2 Operations | [https://learn.microsoft.com/security/](https://learn.microsoft.com/security/) | Band 21 |
| Q72 | Mandiant – Ransomware Exfiltration Techniques: From Rclone to Custom Cloud Connectors | [https://www.mandiant.com/resources/blog](https://www.mandiant.com/resources/blog) | Band 21 |
| Q73 | CISA – Alert AA20-106A: Ransomware Targeting Industrial Control Systems (EKANS / Snake) | [https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a) | Band 22 |
| Q74 | Dragos – Industrial Control Systems Cyber Security Year in Review 2024/2025 | [https://www.dragos.com/year-in-review/](https://www.dragos.com/year-in-review/) | Band 22 |
| Q75 | ISA/IEC 62443 Series – Security for Industrial Automation and Control Systems | [https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series) | Band 22 |
| Q76 | Mandiant – Attackers Innovating in the OT Space: From IT Intrusion to Physical Disruption | [https://www.mandiant.com/resources/blog](https://www.mandiant.com/resources/blog) | Band 22 |
| Q77 | SANS Institute – Memory and Storage Anti-Forensics Analysis | [https://www.sans.org/white-papers/](https://www.sans.org/white-papers/) | Band 23 |
| Q78 | Eric Zimmerman – Tools and Guidance for NTFS Analysis (MFTECmd) | [https://ericzimmerman.github.io/](https://ericzimmerman.github.io/) | Band 23 |
| Q79 | Microsoft Learn – Master File Table (MFT) Architecture Reference | [https://learn.microsoft.com/windows/win32/fileio/master-file-table](https://learn.microsoft.com/windows/win32/fileio/master-file-table) | Band 23 |
| Q80 | NetApp – Technical Report: Protect Against Ransomware with ONTAP Solutions | [https://www.netapp.com/pdf.html?item=/media/16716-tr-4572.pdf](https://www.netapp.com/pdf.html?item=/media/16716-tr-4572.pdf) | Band 24 |
| Q81 | Pure Storage – FlashArray SafeMode Snapshot Architecture & Security Guide | [https://support.purestorage.com/](https://support.purestorage.com/) | Band 24 |
| Q82 | Dell Technologies – PowerStore Cybersecurity and Ransomware Recovery Strategies | [https://www.dell.com/en-us/dt/storage/powerstore-storage-array.htm](https://www.dell.com/en-us/dt/storage/powerstore-storage-array.htm) | Band 24 |
| Q83 | CNCF – Kubernetes Security Best Practices & Pod Security Standards | [https://kubernetes.io/docs/concepts/security/pod-security-standards/](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | Band 25 |
| Q84 | Aqua Security – Cloud Native Threat Report: Ransomware and Cryptominers in K8s | [https://www.aquasec.com/cloud-native-threat-report/](https://www.aquasec.com/cloud-native-threat-report/) | Band 25 |
| Q85 | Sysdig – Threat Research: Analyzing Real-World Attacks on Container Orchestration | [https://sysdig.com/blog/threat-research/](https://sysdig.com/blog/threat-research/) | Band 25 |
| Q86 | CISA / CERT-UA – Joint Advisory on HermeticWiper, CaddyWiper and WhisperGate | [https://www.cisa.gov/news-events/cybersecurity-advisories/](https://www.cisa.gov/news-events/cybersecurity-advisories/) | Band 26 |
| Q87 | Kaspersky Lab – Technical Analysis: NotPetya is a Wiper, Not Ransomware | [https://securelist.com/schroedingers-petya/78870/](https://securelist.com/schroedingers-petya/78870/) | Band 26 |
| Q88 | SentinelOne – Inside HermeticWiper: Anatomy of a Destructive Attack | [https://www.sentinelone.com/labs/hermetic-wiper/](https://www.sentinelone.com/labs/hermetic-wiper/) | Band 26 |
| Q89 | Offensive Security – Kali Linux Official Documentation & Architecture | [https://www.kali.org/docs/](https://www.kali.org/docs/) | Band 27 |
| Q90 | Penetration Testing Execution Standard (PTES) – Technical Guidelines | [http://www.pentest-standard.org/](http://www.pentest-standard.org/) | Band 27 |
| Q91 | NIST SP 800-115 – Technical Guide to Information Security Testing and Assessment | [https://csrc.nist.gov/pubs/sp/800/115/final](https://csrc.nist.gov/pubs/sp/800/115/final) | Band 27 |
| Q92 | Gordon Lyon – Nmap Network Scanning: The Official Nmap Project Guide | [https://nmap.org/book/](https://nmap.org/book/) | Band 27 |

---

## 2. Abdeckungsmatrix

| Dimension | Erreichte Abdeckung | Stand |
|---|---|---|
| Windows-API & Evasion | Vollständig (Band 08, 10, 16, 20) | Q4 2026 |
| Krypto-Mechanik & Datenformate | Vollständig (Band 03, 09, 18, 19, 26) | Q4 2026 |
| Linux & Hypervisor (ESXi) | Vollständig (Band 15) | Q4 2026 |
| Active Directory & Deployment | Vollständig (Band 16) | Q4 2026 |
| Cloud & IaaS (AWS / Azure) | Vollständig (Band 17) | Q4 2026 |
| Incident Response & Recht | Vollständig (Band 05, 17, 19, 26) | Q4 2026 |
| C2-Netzwerk & Exfiltration | Vollständig (Band 11, 21) | Q4 2026 |
| Industrie & OT/ICS | Vollständig (Band 22) | Q4 2026 |
| Anti-Forensik & Log-Neutralisierung | Vollständig (Band 23) | Q4 2026 |
| Enterprise Storage & SAN/NAS | Vollständig (Band 24) | Q4 2026 |
| Kubernetes & Container | Vollständig (Band 25) | Q4 2026 |
| Wiper & Sabotage-Payloads | Vollständig (Band 26) | Q4 2026 |
| Kali Linux & Security Auditing | Vollständig (Band 27) | Q4 2026 |

---

## 3. Status der offenen Punkte (Ausbau-Historie)

Sämtliche offenen Forschungs- und Ausbaupunkte wurden durch die Bände 15 bis 27 vollständig geschlossen:

- [x] **Linux/ESXi-Implementierungspfad:** Durch **Band 15** vollständig erarbeitet.
- [x] **Active-Directory-Intrusion & Domänen-Deployment:** Durch **Band 16** vollständig erarbeitet.
- [x] **Cloud-Ransomware & Multi-Tier Extortion:** Durch **Band 17** vollständig erarbeitet.
- [x] **Post-Quantum-Kryptographie & Hybride KEM:** Durch **Band 18** vollständig erarbeitet.
- [x] **Krypto-Forensik & Decryptor-Bau:** Durch **Band 19** vollständig erarbeitet.
- [x] **EDR-Hook-Evasion & Loader-Architektur:** Durch **Band 20** vollständig erarbeitet.
- [x] **C2-Infrastruktur & Hochvolumen-Exfiltration:** Durch **Band 21** vollständig erarbeitet.
- [x] **OT/ICS- und SCADA-Targeting:** Durch **Band 22** vollständig erarbeitet.
- [x] **Anti-Forensik & Log-Neutralisierung:** Durch **Band 23** vollständig erarbeitet.
- [x] **Enterprise-Storage & SAN/NAS-API-Targeting:** Durch **Band 24** vollständig erarbeitet.
- [x] **Kubernetes & Cloud-Native-Ransomware:** Durch **Band 25** vollständig erarbeitet.
- [x] **Wiper-Mechanik vs. Scheinkryptographie:** Durch **Band 26** vollständig erarbeitet.
- [x] **Kali Linux & Pentesting-Toolchains:** Durch **Band 27** vollständig erarbeitet.

Die Wissenssammlung ist damit inhaltlich und architektonisch vollständig arrondiert.
