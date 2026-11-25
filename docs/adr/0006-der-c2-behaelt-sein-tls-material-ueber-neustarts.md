# ADR-0006: Der C2 behält sein TLS-Material über Neustarts

- **Status:** Accepted
- **Date:** 2026-11-25
- **Related:** Issue #65, ADR-0002 (C2-Transport im Kern)

## Context

Der C2-Server erzeugte bei jedem Start ein neues selbstsigniertes Zertifikat
(`kx_tls::generate_server_tls`) und behielt den privaten Schlüssel nur im
Speicher. Jeder Agent pinnt das Zertifikat über `--server-cert`. Nach einem
Neustart des Servers passte das gepinte Zertifikat nicht mehr zum neuen
Schlüsselpaar — der Agent brach mit `invalid peer certificate: BadSignature`
ab. Im Betrieb hieß das: jeder Neustart des C2 nahm allen Agenten die
Verbindung, bis der Operator das neue Zertifikat von Hand verteilte. Beim
Deploy der Architektur-Runde vom 2026-11-16 ist genau das passiert.

Issue #65 forderte zwei Dinge zugleich:

1. Der Agent kommt über einen Server-Neustart hinweg, ohne sein gepinntes
   Zertifikat zu erneuern.
2. Der private Schlüssel bleibt ausschließlich im Speicher und wird zu keinem
   Zeitpunkt geschrieben.

**Diese beiden Forderungen sind kryptografisch unvereinbar.** TLS bindet das
Zertifikat an sein Schlüsselpaar: der Server beweist im Handshake den Besitz
des privaten Schlüssels, der zum öffentlichen Schlüssel im Zertifikat gehört.
Ein beim Neustart frisch erzeugter Schlüssel zum persistierten Zertifikat
scheitert schon an `rustls::ServerConfig::with_single_cert` (Schlüssel passt
nicht zum Zertifikat) — und erst recht am Agenten. Nur ein persistiertes
**Paar** aus Zertifikat und Schlüssel übersteht den Neustart.

## Decision

Zertifikat **und** privater Schlüssel persistieren nebeneinander, Default
neben der Datenbank (`kx-server.crt` / `kx-server.key` im Verzeichnis von
`--db`). Die Pfade sind per `--cert` und `--key` überschreibbar.

- Beim ersten Start (beide Dateien fehlen) wird ein neues Paar erzeugt und
  abgelegt.
- Bei jedem weiteren Start (beide Dateien liegen) wird dasselbe Paar geladen.
- Liegt nur eine der beiden Dateien, wird der Start abgelehnt statt
  stillschweigend ein neues Paar zu erzeugen — eine Rotation würde die
  gepinnten Zertifikate aller Agenten brechen.
- Der Schlüssel wird atomar geschrieben (temporäre Datei, Rechte setzen,
  umbenennen) und bekommt unter Unix `0600` — denselben Schutz wie die
  Datenbank neben ihm.

Die Forderung „Schlüssel nie auf Platte" aus Issue #65 wird damit bewusst
**nicht** erfüllt; sie ist mit dem eigentlichen Ziel (Neustart-Überleben der
Agenten) nicht vereinbar. Das Ziel hat Vorrang, die Abweichung steht hier.

## Consequences

- Agenten überstehen einen Server-Neustart, ohne dass der Operator ein neues
  Zertifikat verteilt. Der Stolperstein im Runbook `docs/runbooks/windows-test.md`
  wird zur Regel.
- Der private Schlüssel liegt auf der Platte. Er ist kein öffentliches
  Material, aber die Datenbank neben ihm hält bereits die Beute des Betriebs —
  `0600` im Besitz des Dienstbenutzers ist derselbe Schutz. Das Verzeichnis
  gehört dem Betrieb, nicht dem Repository; die Dateien sind gitignored.
- Ein Wechsel der `--cn` erfordert das Entfernen beider Dateien, sonst lädt
  der Server das alte Zertifikat mit dem alten Namen weiter.
- `kx_tls::generate_server_tls` bleibt als reine Erzeugung bestehen;
  `load_or_generate_server_tls` ist die neue Einstiegstelle des Servers.
- Ein Test belegt den Neustart-Fall bis zum Handshake: ein Agent, der das
  Zertifikat des ersten Starts pinnt, handelt gegen die geladene Config des
  zweiten Starts erfolgreich aus.
