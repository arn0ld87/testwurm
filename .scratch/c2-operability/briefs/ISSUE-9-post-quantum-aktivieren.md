# Agent Brief — ISSUE-9

**Category:** bug
**Summary:** Das Modul für die hybride Post-Quantum-Verschlüsselung der Beute ist auskommentiert und wird nicht kompiliert.

**Current behavior:**
Das KEM-Modul des Kern-Crates ist auskommentiert und damit inaktiv. Der Agent
sendet die Master-Key-Felder des C2-Vertrags leer. Die Beute wird unverschlüsselt
übertragen, obwohl das Kern-Crate den Schutz im Namen der Verschlüsselung
verspricht. Das Modul ist zudem gegen eine `ml-kem`-Version geschrieben, die es in
der aufgelösten Version des Workspace-Pins nicht gibt — der Pin ist auf eine
konkrete Version festgenagelt, die API des Moduls passt dazu noch nicht.

**Desired behavior:**
Das KEM-Modul kompiliert, erzeugt echtes Schlüsselmaterial (keine Null-Bytes),
verschlüsselt und entschlüsselt eine Beute verlustfrei, und das Material wird nach
Gebrauch genullt. Die Wire-Felder werden mit echtem Material gefüllt.

**Key interfaces:**
- Die Modul-Deklaration im Kern-Crate: aktiv, kompiliert.
- `derive_master_key()`: liefert echtes HKDF-Material.
- Der Seal/Unseal-Roundtrip: im X25519-only-Modus schließbar, konsistente Längen.
- `MlKemSecret` und die X25519-Secrets: Zeroize beim Drop.
- Die C2-Vertragsfelder für das versiegelte Master-Key-Material: der Agent füllt sie
  mit echtem Material; Server und Agent behandeln sie tolerant, solange das Material
  optional bleibt.
- Die `ml-kem`-Importe: passend zur aufgelösten Version des Workspace-Pins.

**Acceptance criteria:**
- [ ] Das KEM-Modul des Kern-Crates ist aktiv und kompiliert
- [ ] Die Master-Key-Ableitung liefert echtes HKDF-Material, keine 32 Null-Bytes
- [ ] Der Seal/Unseal-Roundtrip ist im X25519-only-Modus schließbar, die Längen sind
      konsistent
- [ ] Die `ml-kem`-Importe passen zur aufgelösten Version des Workspace-Pins
- [ ] Die geheimen Schlüssel werden nach Gebrauch genullt
- [ ] Ein Test deckt den vollständigen Roundtrip ab: Material erzeugen, öffentlichen
      Teil exportieren, einschließen, entschlüsseln, Klartext stimmt
- [ ] Die bestehenden Vertrags-Fixtures bleiben grün

**Out of scope:**
- Änderungen an der Feldmenge des C2-Vertrags — die Felder existieren bereits
- Der Credential-Stuffing-Pfad
- Eine Hochleistungs-Implementierung; Klartextvergleichbarkeit reicht
