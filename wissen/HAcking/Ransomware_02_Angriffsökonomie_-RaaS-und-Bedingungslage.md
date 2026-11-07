# Ransomware – Band 2: Angriffsökonomie, RaaS-Modell und Bedingungslage

Stand: Q3-2025-Datenlage plus eigene Einordnung. Quellen am Ende.

## Marktdaten Q3 2025 (Check Point Research, Report vom 13.11.2025) [3]

- **85 aktive Erpressergruppen** mit eigenen Data Leak Sites – Höchststand bis dahin.
- **1.592 neue gelistete Opfer im Quartal** (Q2 2025: 1.607; Q3 2024: 1.270 → +25 % Jahresvergleich).
- **Durchschnittlich ca. 535 Opfer pro Monat**, stabil auf historisch hohem Niveau; Q2–Q3 2024 waren es rund 420.
- **Zersplitterung nimmt zu:** Die Top 10 Gruppen stellen nur noch **56 %** aller veröffentlichten Opfer – nach 63 % in Q2 und **71 %** in Q1 2025.
- **47 der 85 Leak-Site-Betreiber publizierten weniger als zehn Opfer** → viele Affiliates arbeiten außerhalb etablierter RaaS-Programme, mit eigener Leak-Site.
- **14 neue Gruppen allein in Q3**, insgesamt **45 neu beobachtete Akteure in 2025**.
- **Aktivste Gruppen Q3 2025:** Qilin (Ø 75 Opfer/Monat, Q1 waren es 36), dann Akira, INC Ransom (23 → 39 pro Monat), Play.
- **Sektoren:** Fertigung und Dienstleistungen am stärksten betroffen; Gesundheitswesen konstant 8 % aller Opfer – auch weil große Akteure wie Play es selektiv meiden.
- **Regional:** Südkorea neu in den Top 10, wegen einer Qilin-Kampagne gegen den Finanzsektor.
- **LockBit 5.0** erschien im September 2025 – mögliches Signal für Re-Zentralisierung von Affiliates unter einer Marke.

## Wirkung von Law-Enforcement – die unbequeme Erkenntnis [3]

- Takedowns zielen auf **RaaS-Infrastruktur und Administratoren** (LockBit, 8Base, BlackSuit), nicht auf die **Affiliates**, die die Intrusion tatsächlich ausführen.
- Deshalb **kein signifikanter Rückgang des Gesamtvolumens** nach hochkarätigen Zuschlägen; Angriffe steigen weiter langsam.
- Mechanismus: Wird eine RaaS-Plattform zerschlagen, **wandern Affiliates zu Alternativprogrammen oder gründen eigene Leak-Sites** – nur kurzzeitige Unterbrechung [3].
- Im laufenden Jahr geschlossene oder dormante Marken laut Report u. a.: RansomHub, 8Base, BianLian, Cactus.
- Qilin warb aggressiv ehemalige RansomHub-Affiliates ab – ein Beispiel für Affiliate-Mobilität als Wachstumstreiber [3].

## Operation Cronos (LockBit-Takedown, Februar 2024) – Referenzfall

- Geführt vom UK National Crime Agency (NCA), EU-weit koordiniert, Ankündigung 19./20.02.2024; LockBit war vor dem Zuschlag das weltweit meist eingesetzte Ransomware-Variant und trug laut eigenen Angaben 20–30 % aller Leak-Site-Opfer bei [4].
- Folgen: Plattformausfall, Übernahme der Leak-Site durch das NCA, Verhaftungen, Beschlagnahme von Infrastruktur und verschlüsselten Backups der Gruppe selbst [4].
- **Lehre für die Praxis:** Ein Takedown ist ein taktischer Erfolg und verschiebt Marktanteile, aber er entfernt keine Angreifer aus dem Markt. Resilienz schlägt Verhinderung.

## Erpressungsmodelle – Stapel statt Stufen

1. **Verschlüsselung** – Klassiker, Availability-Angriff auf Daten [5].
2. **Doppelte Erpressung (Double Extortion)** – Verschlüsselung + Datenexfiltration mit Veröffentlichungsdrohung auf Leak-Site; von Maze ab Ende 2019 geprägt und heute Standard [1].
3. **Dreifache Erpressung (Triple Extortion)** – zusätzlich ein dritter Drohkanal, etwa DDOS gegen den Betrieb, direkte Kontaktaufnahme zu Kunden/Partnern oder zum Management.
4. **Vielfache Erpressung (Multi-Extortion)** – Kombination mehrerer Hebel inkl. Behördendrohung/Compliance-Druck. IBM X-Force zählt seit 2019 praktisch jeden bearbeiteten Vorfall mit doppelter Erpressung [6].
5. **Reine Daten-Erpressung ohne Verschlüsselung** – Trend, der zuletzt wieder zunahm; Angreifer verschieben eher Daten als sie zu verschlüsseln, was Recovery-Kosten senkt, aber den Compliance-Schaden erhält.

## Zahlungsbereitschaft – der Markt kippt Richtung Verweigerung

- **Coveware Q3 2025:** Zahlungsrate nur noch **23 %** der betroffenen Organisationen – niedrigster jemals gemessener Wert; Ø-Zahlung **376.941 USD** (−66 % zum Vorquartal), Median **140.000 USD** (−65 %) [7][8].
- Q4 2025 laut nachfolgenden Auswertungen: Zahlungsrate weiter auf 20 %, Ø-Zahlung wieder 591.988 USD – starke Quartals-Ausschläge, Median als belastbarere Kennzahl [8].
- **Treiber:** Große Unternehmen widersetzen sich zunehmend dem Zahlungsdruck; mehrere hochprofessionelle Datenexfiltrationsfälle ohne Zahlung; verbesserte Recovery-Fähigkeit und Versicherungsbedingungen.
- **Verhandlungspraxis:** Realistische Vergleichsergebnisse liegen deutlich unter der Initialforderung – als Erfahrungswert werden Mediane unterhalb von etwa 10 % der Forderung genannt; Spannen streuen stark [9].

## Ökonomische Logik dahinter (freie Einordnung)

- **Zahlungsquote × Medianpreis** bestimmt den Erwartungswert für Angreifer. Beide sinken, die Opferzahl steigt – für kleine und mittlere Täter rechnet es sich weiter, für die großen Marken sinkt die Marge. Das erklärt die Fragmentierung: Die Markteintrittsbarriere ist durch RaaS und mietbare Initial-Access-Anbieter minimal geworden.
- **Konsequenz für Verteidiger:** Wer glaubt, man könne durch Abschalten von Top-Marken das Risiko senken, irrt. Risiko sinkt nur durch eigene Wiederherstellungsfähigkeit und durch Exfiltrationskontrolle.

## Initiale Zugangswege – Verschiebung zu Identitäten

- **Identitätsgeführter Initial Access** wird in aktuellen Auswertungen mit rund 35 % angegeben, vor Schwachstellen-Ausnutzung mit rund 31 % [10] – Angreifer *loggen* sich ein, statt einzubrechen.
- **KI-generiertes Phishing** hat Volumen und Sprachqualität der Initial-Access-Kampagne deutlich erhöht; RaaS-Industrialisierung und doppelte Erpressung bleiben die strukturellen Trends [11].
- Einzelne Berichte behaupten, KI sei in 84 % der Angriffe beteiligt; diese Zahl ist methodisch weich und sollte als Trendaussage, nicht als Messwert behandelt werden [12].

## Quellen

- [3] Check Point Research – The State of Ransomware, Q3 2025 (13.11.2025): https://research.checkpoint.com/2025/the-state-of-ransomware-q3-2025/
- [4] NCA – Operation Cronos: https://www.nationalcrimeagency.gov.uk/the-nca-announces-the-disruption-of-lockbit-with-operation-cronos · Trend Micro – Operation Cronos' Impact: https://www.trendmicro.com/en/research/24/c/operation-cronos-aftermath.html · Wikipedia LockBit: https://en.wikipedia.org/wiki/LockBit
- [1] Maze/Double Extortion: CyberDefenders, History of Ransomware: https://cyberdefenders.org/cybersecurity-glossary/history-of-ransomware/
- [6] IBM – What Is Ransomware: https://www.ibm.com/think/topics/ransomware
- [7] Coveware – Insider Threats Loom while Ransom Payment Rates Plummet (10/2025): https://coveware.com/2025/10/insider-threats-loom-while-ransom-payment-rates-plummet/ · SecurityWeek-Auswertung: https://www.securityweek.com/ransomware-payments-dropped-in-q3-2025-analysis/
- [8] Stingrai – Ransomware Payout Statistics 2026: https://www.stingrai.io/blog/ransomware-payout-statistics-2026
- [9] cybernotfall24 – Ransomware-Lösegeld richtig verhandeln: https://cybernotfall24.de/blog/ransomware-loesegeld-verhandeln
- [10] Axis Intelligence – Identity-Based Attack Statistics 2026: https://axis-intelligence.com/identity-based-attack-statistics/
- [11] Adaptive Security – Ransomware Trends 2026: https://www.adaptivesecurity.com/blog/ransomware-trends-2026
- [12] CBS News – AI linked to 84% of ransomware attacks: https://www.cbsnews.com/news/ai-linked-ransomeware-attacks-global-cybersecurity-report/
