# Agent Brief — ISSUE-11

**Category:** bug
**Summary:** Die Argumentstruktur des Agenten leitet Debug ab und gibt damit das C2-Token im Klartext aus.

**Current behavior:**
Die Argumentstruktur des Agenten leitet Debug ab. Das Token steckt als String in
einem Feld dieser Struktur. Jede Debug-Ausgabe der Argumente — etwa ein
versehentliches Log beim Start — enthält den Zugangsschlüssel im Klartext. Aktuell
wird die Struktur nirgends debug-ausgegeben, das Risiko ist aber strukturell
eingebaut. Die Operator-CLI hat ihre Argumentstruktur ohne Debug-Ableitung — das
ist der Zielzustand.

**Desired behavior:**
Eine Debug-Ausgabe der Agent-Argumente enthält das Token nicht. Entweder die
Struktur leitet Debug nicht mehr ab, oder das Token-Feld ist so gekapselt, dass
eine Debug-Ausgabe den Wert maskiert.

**Key interfaces:**
- Die Argumentstruktur des Agenten: Debug-Ableitung entfernen oder das Token-Feld
  mit einem eigenen Typ kapseln, dessen Debug den Wert maskiert (etwa
  `f.debug_struct("Args").field("token", &"***").finish()`).
- Der Token-Typ in der Operator-CLI: dort ist keine Debug-Ableitung vorhanden — der
  gewünschte Zustand.

**Acceptance criteria:**
- [ ] Eine Debug-Ausgabe der Agent-Argumente enthält das Token nicht
- [ ] Kein Debug-Ausdruck gibt das Token im Klartext aus
- [ ] Ein Test prüft, dass die Debug-Ausgabe der Argumente das Token nicht enthält
- [ ] Das Verhalten der CLI-Argumente bleibt unverändert

**Out of scope:**
- Der Zugangsschlüssel im Debug-Output des Servers (eigene Prüfung)
- Eine Rotation oder Ablaufzeit für Token
