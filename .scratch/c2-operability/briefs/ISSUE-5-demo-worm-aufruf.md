# Agent Brief — ISSUE-5

**Category:** bug
**Summary:** Der Nutzungskommentar des Beispiel-Binaries nennt ein CLI-Flag, das der Parser nicht kennt.

**Current behavior:**
Der Nutzungskommentar des Beispiels empfiehlt einen Aufruf mit einem Bereichs-Flag.
Der Argument-Parser des Agenten kennt nur getrennte Start- und End-Angaben. Der
kopierte Aufruf bricht mit einem Parser-Fehler ab, bevor das Beispiel überhaupt läuft.

**Desired behavior:**
Der Nutzungskommentar nennt einen Aufruf, den der Parser akzeptiert — vollständig
und kopierbar.

**Key interfaces:**
- Der Argument-Parser des Agenten: Schnittstelle sowie getrennte Start- und
  End-Angabe.
- Der Rustdoc-Kopf des Beispiel-Binaries.

**Acceptance criteria:**
- [ ] Der Nutzungskommentar nennt nur Flags, die der Parser akzeptiert
- [ ] Der Kommentar enthält ein vollständiges, kopierbares Beispiel mit Schnittstelle
      sowie Start- und End-Angabe
- [ ] Der genannte Aufruf lässt sich ohne Parser-Fehler ausführen

**Out of scope:**
- Eine Bereichs-Shorthand-Syntax im Parser
- Das Verhalten des Beispiels selbst
