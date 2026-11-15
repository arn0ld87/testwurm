# Agent Brief — ISSUE-4

**Category:** bug
**Summary:** Die Credential-Manager-Extraktion liefert bei genau einem gespeicherten Credential eine leere Liste.

**Current behavior:**
Die PowerShell-Sammlung wird mit `ConvertTo-Json` serialisiert. PowerShell serialisiert
ein einzelnes Element als JSON-Objekt, nicht als Array. Der Deserialisierer erwartet
eine Liste; das Scheitern wird als leeres Ergebnis behandelt. Damit verschwindet
genau der häufigste Sonderfall — ein einzelnes gespeichertes Credential.

**Desired behavior:**
Ein gespeichertes Credential wird als ein-elementige Liste geliefert, mehrere
Credentials als mehr-elementige Liste. Ein JSON-Parse-Fehler erzeugt eine Warnung
im Log, kein stilles Weglassen.

**Key interfaces:**
- `extract_credential_manager()`: die Rückgabe bleibt `Result<Vec<Secret>, WinError>`.
- Der PowerShell-Collector: die Serialisierung muss unabhängig von der Elementzahl
  ein Array erzeugen.
- `parse_secrets_from_json()`: der Fehlerpfad wird auf eine Log-Warnung umgestellt,
  statt still zu leeren.

**Acceptance criteria:**
- [ ] Eine Ausgabe mit genau einem Credential ergibt eine Liste mit einem Eintrag
- [ ] Eine Ausgabe mit mehreren Credentials ergibt eine Liste mit mehreren Einträgen
- [ ] Ein JSON-Parse-Fehler erzeugt eine Log-Warnung und kein stilles leeres Ergebnis
- [ ] Ein Test deckt den Ein-Fall und den Mehr-Fall ab (Ausgabe als String-Fixture,
      kein Windows-Zielsystem nötig)

**Out of scope:**
- Die LSASS- und die Browser-Credential-Extraktion
- Das Format der `Secret`-Felder
