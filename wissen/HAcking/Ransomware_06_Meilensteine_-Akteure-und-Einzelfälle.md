# Ransomware – Band 6: Meilensteine, Akteure und Einzelfälle

Stand August 2026. Fälle sind nach ihrer **Wirkung auf das Feld** ausgewählt, nicht nach Schaden sortiert.

## 1. Die dreizehn Fälle, die das Feld verändert haben

### AIDS Trojan / PC Cyborg (1989)
- ~20.000 Disketten per Post an WHO-Konferenzteilnehmer, nach 90 Reboots Datei-Chaos, 189 USD Forderung nach Panama [1].
- **Bedeutung:** Erstes dokumentiertes Erpressungsmodell; alle drei damaligen Schwächen (brechbare Krypto, physische Distribution, nachverfolgbare Zahlung) wurden in den Folgejahrzehnten abgebaut [1].

### GpCode (2004/05) und Archiveus (2006)
- E-Mail-Verbreitung, RSA-1024-Bit aufwärts; Archiveus als frühe RSA-Anwendung auf den Dokumente-Ordner [1].
- **Bedeutung:** Krypto wurde zum Standard; Wiederherstellung ohne Betreiberschlüssel unmöglich [1].

### Reveton / Ukash & Gov (ca. 2012)
- Locker per Drive-by-Download, falsche FBI-/Polizeimeldung, "Bußgeld" [1].
- **Bedeutung:** Etablierte die Maschine als Geisel, nicht nur Dateien; Skala durch Scareware [1].

### CryptoLocker (2013)
- infizierte Mail-Anhänge, RSA-2048, Bitcoin-Forderung; Nachahmer CryptoWall, TeslaCrypt [1].
- **Bedeutung:** Anonyme, globale Zahlung machte Ransomware zum wiederholbaren Geschäftsmodell [1].

### WannaCry (Mai 2017)
- EternalBlue (SMB, NSA-Leak), Wurmkomponente, über 200.000 Systeme in ~150 Ländern, NHS hart getroffen; Patch existierte vor dem Ausbruch [1].
- **Bedeutung:** Internet-Skalierung ohne menschlichen Verteiler; Patching-Disziplin als Sicherheitsfaktor mit Rechenbeispiel; zugleich der Fall, der Ransomware in die Geschäftsführungsebene hob.

### NotPetya (Juni 2017)
- gleicher Vektor, aber MBR und MFT überschrieben, kein Recovery-Pfad; **Wiper im Ransomware-Mantel**, Milliardenschaden [1].
- **Bedeutung:** Die Grenze zwischen Erpressung und Zerstörung ist politisch/strategisch dünn; Lieferkettenangriff über eine ukrainische Buchhaltungssoftware; Versicherungsklagen um "Kriegsklauseln" (Axa/Mondelez) wurden Follow-up-Thema.

### GandCrab (2018)
- erster großer RaaS-Verkauf mit Affiliate-Modell und „Profitorientierung nach außen“ (freiwillige Entschlüsselungskosten-Deckelung).
- **Bedeutung:** Blaupause für die RaaS-Ökonomie, die Maze und LockBit später skalierten (freies Fachwissen).

### Maze (2019)
- **Pionier der doppelten Erpressung:** Exfiltration vor Verschlüsselung, Leak-Site mit Veröffentlichungsdrohung; Modell binnen Monaten Branchenstandard [1].
- **Bedeutung:** Backup verlor seine Alleinstellung als Antwort; Abwehr musste zu Lateralmovement und Data Staging vorwandern [1]. Maze „sunsettete“ 2020 und übergab sein Datenarchiv an Sodinokibi/REvil – ein seltener Blick in die Backstage-Ökonomie (freies Fachwissen).

### Ryuk (2018–2021)
- typische Kette: Emotet-Trainer → Credential-Diebstahl → manueller AD-Einbruch → Ryuk-Detonation.
- **Bedeutung:** Etablierte das Modell „Malware als Türöffner, Ransomware als Cash-out" und die Rolle von Initial-Access-Brokern als eigenem Marktsegment (freies Fachwissen).

### DarkSide / Colonial Pipeline (Mai 2021)
- DarkSide-Affiliate kompromittierte die größte US-Treibstoffpipeline [1].
- **Bedeutung:** Ransomware als Infrastruktur- und Tagespolitik-Thema; DarkSide löste sich nach US-Zahlungsverfolgung kurz darauf auf; Payment-Rückforderung durch FBI wurde Präzedenzfall für Krypto-Trace-Fähigkeit (freies Fachwissen).

### Kaseya VSA / REvil (Juli 2021)
- Supply-Chain-Angriff über das Kaseya-Managementtool, tausende MSP-Kunden gleichzeitig, weltweite Produktionsstopps (u. a. Coop Schweden).
- **Bedeutung:** Ein Tool-Hersteller kann ein Single Point of Failure für tausende Mandanten sein; MSP- und Remote-Management-Sicherheit wurde eigenständiges Prüffeld (freies Fachwissen).

### LockBit – Aufstieg, Takedown, Rückkehr
- Vor dem Zuschlag meistverbreitetes RaaS weltweit; **Operation Cronos** (NCA, 19./20.02.2024) mit Verhaftungen, Infrastruktur-Beschlagnahme und Leak-Site-Übernahme [2].
- **Bedeutung:** Selbst der erfolgreichste Takedown der Geschichte senkte das Angriffsvolumen nicht strukturell, weil Affiliates abwanderten [2][3]. **LockBit 5.0** erschien im September 2025 [3].

### Change Healthcare / ALPHV·BlackCat (Februar 2024)
- Angriff auf den Abrechnungs-Intermediate der US-Gesundheitsversorgung; massiver Abrechnungsstillstand, danach Gruppenspaltungen und Leak-Site-Manipulationen in der Szene (freies Fachwissen).
- **Bedeutung:** Ein einzelner Zwischenhändler/Dienstleister kann sektorweite Resilienz kippen; Ransomware traf erstmals flächig ein Zahlungssystem.

## 2. Akteurslandkarte Q3 2025 [3]

| Rang | Gruppe | Ø Opfer/Monat | Bemerkung |
|---|---|---|---|
| 1 | **Qilin** | ~75 (Q1: 36) | wirbt aggressiv Ex-RansomHub-Affiliates ab |
| 2 | **Akira** | hoch | ChaCha20/ChaCha8-Verschlüsselung [4] |
| 3 | **INC Ransom** | 23 → 39 | Wachstum nach RansomHub-Wegfall |
| 4 | **Play** | stabil | meidet das Gesundheitswesen selektiv |
| – | **LockBit 5.0** | – | Re-Marktbildung seit 09/2025 |

- **85 aktive Gruppen**, Top 10 nur noch 56 % der Publikationen, 45 neue Akteure in 2025, 47 von 85 Leak-Sites mit unter zehn Opfern [3].
- **2025 geschlossene oder dormante Marken:** RansomHub, 8Base, BianLian, Cactus u. a. [3].
- **Sektoren:** Fertigung und Dienstleistungen führen, Gesundheitswesen stabil bei 8 % der Opfer [3].
- **Südkorea** neu in den Top-10-Ländern (Qilin-Kampagne gegen Finanzsektor) [3].

## 3. Wichtige Familien nach technischer Signatur (freies Fachwissen)

| Familie | Technische Eigenheit |
|---|---|
| **Maze** | Exfiltration + Leak-Site, Double Extortion als Blaupause |
| **Sodinokibi/REvil** | VSS-Löschung über `DeviceIoControl` statt Kindprozess – leiser Weg [5] |
| **Babuk** | Source-Leak 2021 → zehn Folgefamilien mit ESXi-Lockern [6] |
| **LockBit 3.0** | Rollback-/Entschlüsselungsfehler in frühen Builds, Decryptor-Probleme |
| **BlackCat/ALPHV** | Rust-Implantat, Bootstart-Verschlüsselungsoption, mehrsprachige Notes |
| **Akira** | ChaCha20/ChaCha8, teilweise Teilmengenverschlüsselung großer Dateien [4] |
| **Play** | langsamer Verschlüsselungsstart nach Boot, Vermeiden von AV-Prozessen |
| **Medusa** | AES-256 mit `.medusa`-Extension und Ransom-Note-Flag, im T1486-Kontext genannt [4] |
| **Kyber** | Hybrid-Krypto (AES-256-CTR mit X25519 und Kyber) – frühes Post-Quantum-Signal im Feld |

## 4. Was die Fallgeschichte für Architekturentscheidungen bedeutet (freie Einordnung)

1. **Patch- und Konfigurationshygiene schlägt Malware-Intelligenz** – WannaCry mit vorhandenem Patch.
2. **Der Schwachpunkt wandert:** Endpoint → Identität → Edge-Gerät → Hypervisor → Lieferant/Managed-Service → SaaS-API.
3. **Backup ohne Trennung ist kein Backup** – Nicht jeder Fall, aber sehr viele zeigen Backup-Kompromittierung als Ergebnisverstärker.
4. **Lösegeldverweigerung ist kein Risikoausschluss**, sondern eine Kalkulation, die saubere Recovery und Exfiltrationsbewertung voraussetzt.
5. **Gruppennamen sind Marketing, keine Technik:** dieselben Akteure wechseln Marken und Tools; Analyse muss Verhalten und Infrastruktur matchen, nicht Labels.

## Quellen

- [1] CyberDefenders – History of Ransomware: From Floppy Disk to RaaS: https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/
- [2] NCA – Operation Cronos: https://www.nationalcrimeagency.gov.uk/the-nca-announces-the-disruption-of-lockbit-with-operation-cronos · Trend Micro – Operation Cronos' Impact: https://www.trendmicro.com/en/research/24/c/operation-cronos-aftermath.html · Europol: https://www.europol.europa.eu/media-press/newsroom/news/law-enforcement-disrupt-worlds-biggest-ransomware-operation · Wikipedia LockBit: https://en.wikipedia.org/wiki/LockBit
- [3] Check Point Research – The State of Ransomware Q3 2025 (13.11.2025): https://research.checkpoint.com/2025/the-state-of-ransomware-q3-2025/
- [4] MITRE ATT&CK T1486 – Procedure Examples (Akira, Medusa): https://attack.mitre.org/techniques/T1486/
- [5] Picus Security – Technique to Delete Volume Shadow Copies (DeviceIoControl / Sodinokibi): https://www.picussecurity.com/resource/blog/technique-to-delete-volume-shadow-copies-deviceiocontrol
- [6] SentinelOne Labs – Hypervisor Ransomware / Babuk-Leak: https://www.sentinelone.com/labs/hypervisor-ransomware-multiple-threat-actor-groups-hop-on-leaked-babuk-code-to-build-esxi-lockers/

## Hinweis zur Belastbarkeit

Die mit „freiem Fachwissen“ markierten Passagen stützen sich auf meine Wissensbasis, nicht auf die zitierten Quellen. Fall-Details (Infiziertenzahlen, Schadenhöhe) variieren je nach Quelle erheblich; wo eine Zahl nur in einer Quelle stand, ist sie als Einzelbehauptung zu lesen.
