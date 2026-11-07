# Ransomware – Band 5: Abwehr, Incident Response und Rechtslage

Stand August 2026. Deutschland-Bezug explizit ausgewiesen. Quellen am Ende.

## 1. Die drei Säulen der Abwehr

Der aktuelle Konsens für den Mittelstand gliedert in **Prävention** (Initial Access blockieren), **Detection** (frühes Erkennen) und **Recovery** (3-2-1-Backup mit Air-Gap) [1]. Das ist kein Additiv-Programm: Fällt eine Säule, tragen die anderen beiden nicht.

### 1.1 Prävention

- **Identität zuerst:** MFA auf allen externen Zugängen, Conditional Access, keine Admin-Konten für Mail/Internet, Tier-Modell für Active Directory. Hintergrund: identitätsgeführter Initial Access liegt vor der Exploit-Ausnutzung [2].
- **Patch-Management als historischen Beleg:** WannaCry war durch einen bereits existierenden Patch vermeidbar; das Desaster kam von ungepatchten Systemen [3].
- **Segmentierung** Ost/West, Admin-Netze, eigenes Management-VLAN, Blockieren von SMB zwischen Client-Subnetzen.
- **Härtung:** LSA Protection, Credential Guard, WDAC/AppLocker, Deaktivierung unnötiger Ausführungspfade, No-Admin-Workstations.
- **ESXi/Hypervisor separat betrachten:** kein Endpoint-Agent dort, daher Zugangslisten, SSH-Zugang einschränken, Alt-Hosts ersetzen [4].

### 1.2 Backup – die Regelkette

| Regel | Bedeutung |
|---|---|
| **3-2-1** | 3 Kopien, 2 Medienarten, 1 Kopie außer Haus [5] |
| **3-2-1-1-0** | plus 1 **offline/offsite immutable** Kopie und 0 Fehler bei verifizierten Restores [6] |
| **Air-Gap / Air-Gapped** | Netzwerk-Trennung der Backup-Appliance, kein Domänenbeitritt des Backup-Servers |
| **Immutable Storage** | Object-Lock / WORM, auch mit Admin-Rechten nicht löschbar binnen Retention |

**Kritische Einwände gegen naive Backup-Strategien:**

- Backups sind **Teil der Angriffsfläche, nicht der Schutzwall**: Sophos dokumentiert, dass kompromittierte Backups das Ergebnis messbar verschlechtern [7].
- Lösch-Mechanismen auf Array-Seite (Snapshots von NetApp/Synology, `wbadmin`, Veeam-Repository) werden von modernen Familien aktiv mitgenommen (freies Fachwissen, deckt sich mit [7]).
- Ein Backup ohne **getesteten Restore** ist eine Vermutung, keine Fähigkeit.

### 1.3 Detection

- EDR mit Tamper-Protection auf allen Endpoints, plus Logging auf Identitäts- und Netzwerkseite.
- **Canary-/Honeytoken-Architektur:** platzierte Köderdateien je Fileshare, SACL-Audit, FSRM-File-Filter, automatisiertes Containment bei Berührung [8].
- **VSS-Tampering als Alarm**, nicht als Fußnote: Shadow-Copy-Löschung kündigt die Verschlüsselung an; Command-Line-Audit aktivieren und auf die kleine feste Menge von Löschkommandos alarmieren [9].
- **Exfiltrationskontrolle:** Egress-Whitelist, DLP, Anomalie auf Volumina; ohne diese Kontrolle bleibt doppelte Erpressung unbeantwortet.

## 2. BSI-Empfehlungen (deutscher Referenzrahmen)

Die BSI-Empfehlungen gegen Ransomware im Überblick – über die NCS-Zusammenfassung belegt [10]:

- **keine Zahlungen an Cyberkriminelle** tätigen (BSI-Grundhaltung, keine Rechtsprechung)
- regelmäßige, **getestete** Sicherungen
- aktuelle Patches, Aktivierung von Windows-Schutzmechanismen
- Rechte-Minimierung und Benutzeraufklärung
- getrennte Netze und Backup-Trennung

## 3. Incident-Response-Ablauf (Praxis)

1. **Containment vor Analyse:** infizierte Segmente netzwerkseitig trennen, aber **nicht** herunterfahren – Speicherforensik und In-Memory-Schlüssel gehen sonst verloren.
2. **Zeitstempel nehmen** vor jeder Veränderung; erste Priorität ist die Bestimmung des Exfiltrationszeitraums, nicht die Bestimmung des Familiennamens.
3. **Isolierte Entschlüsselungsstrecke** aufbauen, Key-Extraktion nur in der Sandbox, nicht auf dem Produktivsystem.
4. **Backups prüfen, bevor sie benutzt werden:** Integritätscheck auf Infektionsstand Alter, sonst wird die Hintertür mit zurückgespielt.
5. **Parallel verhandeln und rekonstruieren** – Negotiation ist Zeitkauf, nicht Schuldeingeständnis.
6. **Beweissicherung** für Versicherung und Strafverfolgung; Forensik-Bericht revisionssicher.
7. **Lektionenschleife** dokumentieren, bevor das Team auseinandergeht.

## 4. Lösegeldzahlung – Rechtslage Deutschland

**Kern: Es gibt keinen Rechtssatz, der die Zahlung von Lösegeld bei Ransomware pauschal unter Strafe stellt.** Wer erpresst wird, ist Opfer einer Straftat [11].

Gleichwohl existieren Risiken, die eine Zahlung strafrechtlich einfärben können:

- **Unterstützung einer kriminellen Vereinigung (§ 129m StGB, früher § 129 StGB):** Behörden und ein Teil der Literatur sehen in der Zahlung einen möglichen Eingriff in die öffentliche Sicherheit/Ordnung; die Zahlung kann als Unterstützung gewertet werden, wenn die Organisation als kriminelle Vereinigung einzustufen ist und kein Rechtfertigungsgrund greift [12][13].
- **Rechtfertigender Notstand (§ 34 StGB) / Nötigungsnotstand:** Die Literatur argumentiert, dass die Zahlung gerechtfertigt sein kann, weil der Unternehmer durch die Erpressung genötigt wird, in Schutzgüter des § 129 StGB einzugreifen [12].
- **Geldwäscheverdacht:** Zahlung in Krypto an unbekannte Empfänger, insbesondere über Mixers, berührt Sorgfaltspflichten (freies Fachwissen; wird in der zitierten juristischen Diskussion mitgeführt [13]).
- **§ 154a StPO:** Verfahrensökonomische Beschränkung der Verfolgung, relevant wenn neben dem erzwungenen Zahlvorgang weitere Gesetzesverstöße im Raum stehen [14].
- **Praktische Konsequenz:** Zahlung vorher **dokumentieren und rechtlich absichern lassen** (Notstandsbegründung, Nachweis der Drucklage, Verhältnismäßigkeit), Versicherer früh einbinden. Die Saarbrücker Rechtszeitschrift diskutiert genau diese Argumentationslinie im Detail [13].

**Behördenhaltung vs. Praxis:** Das BSI rät grundsätzlich zu keiner Zahlung [10]; die Strafverfolgungspraxis akzeptiert Zahlungen typischerweise als Opferhandeln, sobald Notstandslage und Dokumentation stimmen [11][12].

## 5. Compliance und Meldelagen

- **DSGVO:** Bei personenbezogenen Daten ist der Ausfall der Verfügbarkeit selbst ein Incident; die 72-Stunden-Frist der Art. 33 gilt für die Datenschutz-Aufsicht, bei hohem Risiko zusätzlich die Betroffeneninformation (Art. 34). Ob die Veröffentlichung gestohlener Daten eine Meldepflicht auslöst, ist Einzelfallentscheidung – die Frage stellt sich nach der Zahlung nicht weniger als davor (freies Fachwissen).
- **NIS2 (Umsetzung in Deutschland):** sektoral erweiterte Maßnahmen- und Nachweispflichten inkl. Resilienz, Lieferkette und Meldewegen; betrifft Sektoren der kritischen und wichtigen Infrastruktur [15].
- **KRITIS/BSI-KritisV, IT-Sicherheitskatalog** je Sektor; bei Verdacht auf Manipulation im besonderen Ereignis zusätzlich Meldepfade ans BSI.
- **Versicherung:** Police-Klauseln verlangen meist Vorab-Stimmung mit Versicherer und Nutzung benannter Negotiatoren/Forensiker; eigenmächtige Zahlung kann den Schutz kosten (freies Fachwissen).

## 6. Recovery-Kostenrealität

- Die Zahlung ist selten der größte Posten: **Business Interruption** dominiert in den meisten Aufstellungen, dazu kommen Reputations- und Rechtskosten (freies Fachwissen, gedeckt durch die Coveware-Systematik [16]).
- **Zahlungsquote sinkt** auf 23 % (Q3 2025), Median 140.000 USD – Verweigerung mit eigener Recovery wird ökonomisch rational [16][17].
- **Verhandlungsrealität:** Vergleiche landen deutlich unter der Initialforderung; Erfahrungswert Median unter etwa 10 % der Forderung, starke Streuung [18].

## Quellen

- [1] BFG IT – Ransomware-Abwehr 2026 (drei Säulen, 3-2-1 mit Air-Gap): https://bfg-it.de/ransomware-abwehr-2026-backup-detection-recovery/
- [2] Axis Intelligence – Identity-Based Attack Statistics: https://axis-intelligence.com/identity-based-attack-statistics/
- [3] CyberDefenders – History of Ransomware (WannaCry/Patching): https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/
- [4] Huntress – Hardening the Hypervisor: https://www.huntress.com/blog/hypervisor-defenses-against-ransomware-targeting-esxi
- [5] a7 – Backup-Strategie 3-2-1 (inkl. Immutable, Air-Gap, RTO/RPO): https://a7.de/blog/datensicherung-strategie-3-2-1/
- [6] IT Guru Online – 3-2-1-1-0 in der Praxis: https://itguruonline.de/backups-gegen-ransomware-schuetzen-offline-und-offsite-kopien-richtig-anlegen/
- [7] Sophos – Kompromittierte Backups bei Ransomware-Angriffen: https://www.sophos.com/de-de/resources/impact-compromised-backups-ransomware-outcomes
- [8] Mjolnir Security – Canary Files and Tripwires: https://intel.mjolnirsecurity.com/detect-canary-files.html
- [9] WinSentinel – Auditing VSS Shadow Copy Tampering: https://winsentinel.ai/blog/auditing-vss-shadow-copy-tampering
- [10] NCS – Welche Maßnahmen gegen Ransomware empfiehlt das BSI: https://www.ncs.de/blog/welche-massnahmen-gegen-ransomware-empfiehlt-das-bsi/
- [11] Cyberangriff-Soforthilfe – Lösegeld zahlen strafbar?: https://cyberangriff-soforthilfe.de/ratgeber/ransomware-loesegeld-zahlen
- [12] GTK Rechtsanwälte – Strafrechtliche Risiken bei Lösegeldzahlungen (18.03.2024): https://www.gtkr.de/aktuelles/2024-03-18-welche-strafrechtlichen-risiken-drohen-bei-loesegeldzahlungen-nach-ransomware-angriffen-380.html
- [13] Stammkötter, SZR 1/2023 – Ist die Zahlung eines Lösegeldes bei Ransomware strafbar?: https://www.uni-saarland.de/fileadmin/upload/fakultaet/r/Saarbruecker_Rechtszeitschrift/Ausgabe12023/Stammkoetter_Ist_die_Zahlung_eines_Loesegeldes_bei_Ransomware_strafbar.pdf
- [14] § 154a StPO: https://www.gesetze-im-internet.de/stpo/__154a.html
- [15] NIS2-EU-Umsetzung (Überblick): https://csc.xevos.eu/skoleni/kyberneticka-bezpecnost-pro-zamestnance_nis2/
- [16] Coveware – Q3 2025 Report: https://coveware.com/2025/10/insider-threats-loom-while-ransom-payment-rates-plummet/
- [17] SecurityWeek – Ransomware Payments Dropped in Q3 2025: https://www.securityweek.com/ransomware-payments-dropped-in-q3-2025-analysis/
- [18] cybernotfall24 – Lösegeld richtig verhandeln: https://cybernotfall24.de/blog/ransomware-loesegeld-verhandeln

## Disclaimer

Dieser Band ist fachliche Wissensablage, keine Rechtsberatung. Die strafrechtliche Bewertung von Lösegeldzahlungen ist in Deutschland nicht höchstrichterlich abschließend geklärt; im Einzelfall ist anwaltlicher Rat einzuholen.
