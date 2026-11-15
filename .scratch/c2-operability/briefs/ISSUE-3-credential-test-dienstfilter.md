# Agent Brief — ISSUE-3

**Category:** bug
**Summary:** Der Default-Credential-Test ignoriert den Ziel-Dienst und versucht SSH-Kombinationen auch gegen beliebige andere Dienste.

**Current behavior:**
`try_default_credentials(host, service)` nimmt einen Dienstparameter entgegen, wertet
ihn aber nicht aus: jeder Aufruf führt denselben SSH-Versuch durch, unabhängig davon,
ob der Dienst "ssh", "smb" oder "rdp" ist. Gegenüber Nicht-SSH-Diensten entstehen
entweder irreführende Fehler oder nutzlose Verbindungsversuche.

**Desired behavior:**
Der Credential-Test führt nur für den Dienst "ssh" einen SSH-Versuch durch. Für
andere Dienste wird der Aufwand erkannt und kontrolliert ohne Verbindungsversuch
beantwortet. Das bestehende Rückgabeverhalten bleibt für Aufrufer unkritisch:
Erfolg liefert einen Treffer, Misserfolg liefert `None` ohne Fehler.

**Key interfaces:**
- `try_default_credentials(host: &str, service: &str)`: der Dienstparameter muss die
  Auswahl steuern; die Signatur bleibt erhalten.
- `DEFAULT_CREDENTIALS`: die Kandidatenliste; eine Einschränkung auf SSH-Dienste
  gehört hierher oder in die aufrufende Logik.
- `Auth`: unverändert; das Feld `service` trägt weiterhin den ertesteten Dienst.

**Acceptance criteria:**
- [ ] Ein Aufruf mit `service == "ssh"` löst einen SSH-Versuch aus
- [ ] Ein Aufruf mit einem anderen Dienst löst keinen SSH-Versuch aus und liefert
      kontrolliert `Ok(None)`
- [ ] Der Erfolgsfall liefert einen Treffer mit passendem `service`-Feld
- [ ] Der Misserfolgsfall liefert `Ok(None)` und keinen Fehler
- [ ] Ein Test deckt Dienstfilter, Erfolgs- und Misserfolgsfall ab

**Out of scope:**
- Der Timeout des Subprozesses (ISSUE-14)
- Credential-Tests für SMB oder RDP — dafür ist keine Implementierung vorgesehen
- Die Auswahl der Credential-Kombinationen

**Entscheidung des Maintainers (2026-11-15):**
Das ursprüngliche Akzeptanzkriterium nannte `russh` 0.54 mit einem Mock-SSH-Server
für Client und Server. Der Maintainer hat entschieden: der bestehende `sshpass`-Ansatz
bleibt, der Timeout kommt obendrauf (ISSUE-14). Die ursprüngliche Werkzeugvorgabe
und der Mock-Server-Test sind damit **nicht** mehr bindend; der Test soll die
beobachtbaren Verhaltensweisen absichern, nicht die konkrete Implementierung.
