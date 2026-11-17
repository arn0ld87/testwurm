# ADR-0005: Die Beute trägt ihren Schlüssel mit

- **Status:** angenommen
- **Datum:** 2026-11-17

## Kontext

Der Agent kapselt je Host einen Master-Key gegen den öffentlichen Server-Schlüssel
und versiegelt damit die Beute. Der Server speichert diesen Schlüssel in der
Host-Zeile (`sealed_master`) und **ersetzt ihn bei jeder Registrierung** — der
Agent erzeugt in jedem Lauf einen neuen.

Ein Host, dessen Beute in einem späteren Lauf nicht erneut gefunden wird, behält
seine alte Zeile. Auf der Kali-VM schlägt der SMB-Relay in jedem Lauf fehl: der
Host wird also in jedem Lauf neu registriert (mit neuem Schlüssel) und seine
Beute nicht erneut hochgeladen. Die Zeile trägt den Chiffretext des **alten**
Schlüssels, der Host-Eintrag führt den **neuen**. Die Beute ist kryptografisch
tot: sie steht da und ist unlesbar — ohne Fehler und ohne Warnung.

## Entscheidung

**Die Beute trägt ihren Schlüssel mit.** Der Upload bekommt das versiegelte
Master-Key des Hosts (`sealed_master` im `SecretUpload`), der Server speichert es
mit der Zeile und gibt es mit der Zeile zurück (`sealed_master` in
`ExfiltratedSecret`). Der Operator entsiegelt es mit dem privaten Server-Schlüssel
und öffnet die Zeile — ohne Rücksicht darauf, welchen Schlüssel der Host-Eintrag
gerade führt.

Damit stirbt die ganze Fehlerklasse: eine Zeile ist für sich lesbar, gleichgültig
was später mit dem Host passiert. Das gilt auch für den Fall, dass eine
Extraktion in einem Lauf ausfällt und die Zeile eines früheren Laufs zurückbleibt.

## Folgen

- Ein **neues Feld in einem Antworttyp** — nach ADR-0001 braucht das Server
  **und** Client gleichzeitig. Ein älterer Operator liest die neue Zeile nicht.
- Der Schlüssel wird je Beutezeile wiederholt (rund 1,5 KiB base64). Das ist
  billig gegenüber der Alternative einer Liste je Host, die mit jedem Lauf wächst.
- Der `sealed_master` der Host-Zeile bleibt: der Server braucht ihn, um den Host
  zuordenbar zu halten. Er ist aber nicht mehr die einzige Quelle des Schlüssels.
- Der Klartextfall bleibt unverändert: ein Agent ohne Server-Schlüssel meldet
  unversiegelt, und die Zeile trägt dann keinen Schlüssel.
- Die Beutezeile ist jetzt für sich lesbar — die Aussage „der Server hält die
  Beute" stimmt ohne Zusatzannahme.
