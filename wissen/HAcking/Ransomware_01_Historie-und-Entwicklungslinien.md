# Ransomware – Band 1: Historie und Entwicklungslinien

Stand: Recherche August 2026. Belegt durch Quellen am Ende jedes Abschnitts; freies Fachwissen ist als solches gekennzeichnet.

## Kernthese

Das Erpressungsmodell ist seit 1989 identisch: Daten blockieren, Geld für die Freigabe verlangen. Gefährlich wurde Ransomware erst, als drei Bedingungen gleichzeitig erfüllt waren: **kryptografisch nicht brechbare Verschlüsselung**, **anonyme Zahlung** und eine **Kriminellensupplychain**, die die Fähigkeit mietbar machte [1].

## Die fünf Epochen

### Epoche 0 – Ursprung: AIDS Trojan / PC Cyborg (1989)

- Joseph Popp verschickte ~20.000 Disketten an Teilnehmer einer WHO-AIDS-Konferenz ("AIDS Information Introductory Diskettes").
- Nach dem 90. Neustart verbarg das Programm Verzeichnisse, verfälschte Dateinamen auf C: und forderte 189 USD auf ein Postschließfach in Panama [1].
- Drei Schwächen definierten die nächsten 30 Jahre Angriffsentwicklung:
  1. **Brechbare Krypto** – symmetrisch, Schlüssel lag in der Malware selbst, Analysten bauten schnell Entschlüsselungstools; die meisten Opfer zahlten nie.
  2. **Physische Distribution** – Post statt Netzwerk, damit langsam und begrenzt.
  3. **Nachverfolgbare Zahlung** – das Postschließfach führte zurück zur Person; Popp wurde verhaftet [1].

### Epoche 1 – Krypto-Reife (2004–2012)

- **GpCode** (ca. 2004/2005): Verbreitung per E-Mail, eigener Algorithmus; frühe Varianten knackbar, spätere mit RSA 1024 Bit und darüber – ohne privaten Schlüssel des Betreibers keine Recovery [1].
- **Archiveus** (2006): eine der ersten RSA-Verschlüsselungen, betraf den Dokumente-Ordner [1].
- **Aufspaltung in zwei bis heute gültige Bauformen** [1]:
  - **Crypto-Ransomware** – verschlüsselt Dateien, Daten bleiben auf der Platte, aber unlesbar.
  - **Locker-Ransomware** – sperrt das Gerät/OS aus, ohne zwingend Einzeldateien zu verschlüsseln.
- **Reveton** (ca. 2012, Lockable/BKASoft): Lockertyp per Drive-by-Download, Bildschirm sperrend mit falscher FBI-/Polizeimeldung und "Bußgeld". Scareware-Erpressung in Skala; etablierte die Idee, die ganze Maschine als Geisel zu nehmen [1].
- **Was sich änderte:** Ransomware wurde technisch nicht mehr rekonstruierbar. Nur noch sauberes Backup oder Betreiberschlüssel halfen. Das ist der Punkt, an dem aus Belästigung ein Geschäftsmodell wurde [1].

### Epoche 2 – Krypto-Zahlung: CryptoLocker (2013–2016)

- **CryptoLocker** (2013) via infizierte Mail-Anhänge und kompromittierte Webseiten; RSA-2048-Bit-Schlüsselpaar auf lokalen und angebundenen Laufwerken; Forderung in **Bitcoin** [1].
- Bitcoin löste das Nachverfolgbarkeitsproblem, das das Panama-Schließfach nie lösen konnte: schnell, global, schwer auf eine Person rückführbar [1].
- Nachahmerfamilie: **CryptoWall**, **TeslaCrypt** u. a. Distribution meist weiter opportunistisch ("spray and pray") [1].
- Kombination nun vollständig: unbrechbare Krypto + anonyme Zahlung + E-Mail-Massenvertrieb [1].

### Epoche 3 – Wurm-Ära: WannaCry und NotPetya (2017)

- **WannaCry** (Mai 2017): über 200.000 Maschinen in rund 150 Ländern innerhalb weniger Tage. Kein menschlicher Klick nötig – selbstdrehende Wurmkomponente auf Basis von **EternalBlue**, einem aus dem NSA-Besitz geleakten SMB-Exploit. Rechner nach Rechner scannte und infizierte er unbepatchte Systeme selbst [1]. Hard getroffen: das britische NHS. **Ein Patch existierte vor dem Ausbruch; das Desaster kam von ungepatchten Systemen** [1].
- **NotPetya** (Juni 2017): gleicher EternalBlue-Vektor, aber **kein echter Ransomwarefall** – MBR und MFT wurden überschrieben, real existierte kein Recovery-Pfad. Ein **Wiper im Ransomware-Mantel**, Milliardenschaden weltweit [1][2].
- **Was sich änderte:** Internet-Skalierung ohne menschlichen Verteiler; die Grenze zwischen Erpressung und reiner Zerstörung ist dünn; die deutlichste Patching-Lektion der Feldgeschichte [1].

### Epoche 4 – Big-Game-Hunting und Doppelte Erpressung (2019–2020)

- Paradigmenwechsel war **strategisch, nicht technisch**: statt zufälliger Opfer gezielte Intrusionen in zahlungsfähige Organisationen. Statt eines Laptops wurde das gesamte Netzwerk auf einmal detoniert [1].
- **Maze** gilt als Begründer der **doppelten Erpressung** (Ende 2019): vor der Verschlüsselung Datenexfiltration und Drohung der Veröffentlichung auf öffentlichem Leak-Site [1].
- **Der entscheidende Effekt:** Doppelte Erpressung brach die einzige Abwehr, die immer funktioniert hatte. Ein solides Backup erlaubt Wiederherstellung und Zahlungsverweigerung – aber ein Backup sagt nichts über bereits gestohlene Daten aus. Addiert wurden Regulierungsstrafen, Klagen und öffentliche Bloßstellung [1].
- Maze' Leak-Site-Modell wurde binnen Monaten branchenstandard [1].
- **Was sich änderte:** Ransomware wurde hand-on-keyboard-Intrusion mit Datendiebstahl, nicht nur Datei-Verschlüsselung. Die Abwehr musste vorwandern zu Lateral Movement und Data Staging [1].

### Epoche 5 – RaaS-Industrialisierung (2020–heute)

- **Ransomware-as-a-Service**: Ein Kern-Entwicklerteam baut und betreibt Malware, Leak-Site und Zahlungsinfrastruktur und vermietet das Paket an **Affiliates**. Affiliates führen die Intrusion durch und teilen die Beute. Entwickler muss niemanden mehr kompromittieren, Affiliate muss keine Malware mehr schreiben [1].
- Folge: Der Angreiferpool weitete sich drastisch, weil für den Einsatz nicht mehr die Fähigkeit zum Bau nötig war [1].
- Symbolfall Mai 2021: Ein DarkSide-Affiliate traf **Colonial Pipeline**, die größte Treibstoffpipeline der USA [1].

## Was jeder Epoche-Wechsel für Verteidiger bedeutet hat

| Epoche | Neuer Verteidigungszwang |
|---|---|
| AIDS Trojan | Malware-Analyse / Entschlüsselungstools |
| Krypto-Reife | Backups, Offline-Kopien |
| Krypto-Zahlung | Krypto-Forensik, Blockchain-Analyse statt Zahlungsverfolgung |
| Wurm-Ära | Patch-Management und Segmentierung |
| Big-Game / Double Extortion | EDR, Lateralmovement-Erkennung, Datenexfiltrationskontrolle |
| RaaS | Threat Intelligence, Affiliate-Tracking, Resilienz statt Verhinderung |

## Freie Einordnung (kein einzelner Beleg)

Die Epochen sind keine Ablösung, sondern **Stapelung**: Lockertyp, Krypto-Wurm, Big-Game-Intrusion und RaaS existieren parallel. Ein Angreifer kombiniert heute Vektoren nach Bedarf – der Verteidiger muss daher alle fünf Verteidigungsebenen gleichzeitig bedienen, nicht nur die neueste.

## Quellen

- [1] CyberDefenders – History of Ransomware: From Floppy Disk to RaaS (Stand Juni 2026): https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/
- [2] Ransomware Protection – History of Ransomware: https://www.ransomware-protection.org/knowledge/history (Seite zeitweise nicht abrufbar; Kernaussagen über WannaCry/NotPetya aus Suchindex)
