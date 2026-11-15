# Agent Brief — ISSUE-14

**Category:** bug
**Summary:** Der SSH-Default-Credential-Test wartet unbegrenzt auf einen hängenden Subprozess und blockiert den Agentenlauf.

**Current behavior:**
Der Credential-Test startet einen SSH-Helfer als Subprozess und wartet auf dessen
Ende — ohne Zeitgrenze und ohne Abbruchmechanismus. Die gesetzte
Verbindungs-Zeitgrenze greift nur für den Verbindungsaufbau; ein Prozess, der
danach hängt (etwa weil er auf eine Eingabe wartet), blockiert den Agentenlauf
endlos. Die Credential-Kombinationen laufen sequenziell, die Wartezeit summiert
sich also auf.

**Desired behavior:**
Jede Kombination hat eine eigene Zeitgrenze, der gesamte Test hat eine Gesamtgrenze.
Danach bricht der Test kontrolliert ab, der Agent beendet sich regulär mit seinen
bisherigen Ergebnissen. Ein fehlendes Hilfsprogramm, eine nicht unterstützte
Eingabeoption und eine abgelaufene Zeitgrenze führen zu einem kontrollierten Fehler.

**Key interfaces:**
- `try_default_credentials()`: verantwortlich für die Zeitgrenzen und die
  Abbruchsteuerung des Subprozesses.
- `ExploitError`: braucht eine Unterscheidung, damit ein Zeitablauf von einem
  fehlenden Hilfsprogramm unterscheidbar ist.
- Die Kandidatenliste der Credentials: ihre Länge bestimmt die Obergrenze der
  Gesamtlaufzeit.

**Acceptance criteria:**
- [ ] Jede Kombination hat eine eigene Zeitgrenze, die Obergrenze über alle
      Kombinationen liegt deutlich unter der bisherigen unbegrenzten Wartezeit
- [ ] Nach Ablauf einer Zeitgrenze bricht der Test kontrolliert ab; der Agent
      beendet sich regulär und meldet seine bisherigen Ergebnisse
- [ ] Ein fehlendes Hilfsprogramm und eine nicht unterstützte Eingabeoption führen
      zu einem kontrollierten Fehler, nicht zu einem Hänger
- [ ] Ein Test deckt den Timeout-Fall ab (Gegenstelle, die nicht antwortet)
- [ ] Die Betriebsdokumentation nennt die Abhängigkeit mit korrekter
      Versionserwartung und den Workaround für den Agentenlauf

**Out of scope:**
- Die Auswahl der Credential-Kombinationen
- Die Wahl des SSH-Client-Werkzeugs — der Maintainer hat am 2026-11-15 entschieden:
  `sshpass` bleibt, es kommt kein Wechsel auf eine Rust-SSH-Bibliothek
- Der Dienst-Filter (ISSUE-3)
