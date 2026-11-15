# Agent Brief — ISSUE-2

**Category:** bug
**Summary:** Das SMB-Relay-Skript fehlt im Repository, wodurch jeder Relay-Aufruf an einer nicht vorhandenen Datei scheitert.

**Current behavior:**
Der Agent scannt Port 445 und ruft für Windows-Hosts mit diesem Port den
SMB-Relay→DCSync-Pfad auf. Dieser startet `python3 <script>` mit einem Skriptpfad,
der auf einen losen Dateinamen im Arbeitsverzeichnis zeigt. Diese Datei liegt nicht
im Repository, ist kein Paketbestandteil und wird nicht mitinstalliert. Jeder Aufruf
endet deshalb, bevor eine Verbindung zum Ziel aufgebaut wird. Der Port-Fix ist
vorhanden, der Ausführungspfad nicht — der Pfad ist erreichbar, aber nicht lauffähig.

**Desired behavior:**
Der SMB-Relay-Pfad ist im Repository enthalten und läuft auf einem Ziel mit offenem
Port 445 zu einem Ergebnis — erfolgreich, fehlgeschlagen oder kontrolliert abgebrochen.
Fehlende Abhängigkeiten (Python, Impacket) führen zu einer klaren Fehlermeldung,
nicht zu einem stillen Erfolgsbild.

**Key interfaces:**
- `RelayConfig`: das Feld `script_path` muss auf ein mitgeliefertes Asset zeigen
  können; der Default darf nicht mehr auf einen losen Dateinamen im aktuellen
  Arbeitsverzeichnis zeigen.
- `smb_relay_dcsync()`: die Fehlerklassifikation muss "Werkzeug oder Skript fehlt"
  von "Relay fehlgeschlagen" unterscheidbar machen.
- Das Agenten-Argument für den Relay-Pfad (`--relay-script`): die Option bleibt
  nutzbar, ihr Default bezieht sich aber auf das mitgelieferte Asset.
- `service_for_port()`: die Zuordnung Port → Dienst und die tatsächlich gescannte
  Portmenge müssen deckungsgleich bleiben.

**Acceptance criteria:**
- [ ] Das Relay-Skript liegt im Repository, und die Standard-Konfiguration verweist darauf
- [ ] Ein Test belegt, dass Port 445 im Scan-Ergebnis erscheint
- [ ] Fehlt das Skript oder Python, entsteht ein kontrollierter Fehler statt eines Hängers
- [ ] Herkunft und Lizenz des Skripts sind im Repository dokumentiert
- [ ] Jede Zuordnung im Port-zu-Dienst-Mapping ist erreichbar, oder das Mapping wird gekürzt
- [ ] Der Workspace baut und die Test-Suite ist grün

**Out of scope:**
- Der WMI-Pfad (ISSUE-7)
- Der Credential-Stuffing-Pfad (ISSUE-3, ISSUE-14)
- Eine Neuschreibung des Relays in Rust
