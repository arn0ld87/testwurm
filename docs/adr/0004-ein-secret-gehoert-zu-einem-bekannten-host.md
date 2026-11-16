# ADR-0004: Ein Secret gehört zu einem bekannten Host — der Server weist Waisenzeilen ab
Status: accepted
Date: 2026-11-16

## Context

ADR-0001 hat die Host-Kennung in den C2-Vertrag gezogen: sie kommt aus dem
Request und wird nicht mehr aus der IP abgeleitet. Als Begründung steht dort,
Registrierung und Secret-Upload könnten dadurch „nicht mehr auseinanderlaufen".

Das stimmte nicht. Der Agent registriert den Host und meldet danach seine
Beute — aber er verwarf den Fehler der Registrierung (`let _ =`). Schlug die
Registrierung fehl und der Upload der Beute gelang, legte der Server eine
Zeile in `secrets` an, deren `host_id` er nie gesehen hatte. Auf der Tabelle
gab es keinen Fremdschlüssel, und nichts im Baum prüfte die Beziehung.

Eine solche Zeile ist eine Waisenzeile: für den Operator ist sie wertlos, weil
er sie keinem Zielhost zuordnen kann. Sie füllt trotzdem die Liste der
Beute und lässt den Bestand größer aussehen, als er ist.

Die Zusage aus ADR-0001 galt nur für den Agenten, der sie einhielt — und der
hielt sie nicht einmal ein. Ein Server, der die Beziehung nicht selbst prüft,
kann sie nicht zusichern: ein älterer Agent oder ein anderer Client hat die
Reihenfolge nicht.

## Decision

Der Server weist einen Secret-Upload ab, dessen `host_id` er nicht kennt. Der
Upload wird mit **400 Bad Request** beantwortet, nicht mit einem
Serverfehler: die Anfrage ist falsch, nicht der Server.

Die Prüfung liegt in der Datenbank, neben der Zeile, die sie betrifft — nicht
im HTTP-Handler. Es ist eine Eigenschaft der Ablage, nicht des Transports.
Der Handler bildet den Fehler nur noch auf einen Status ab.

Der Agent registriert den Host vor seiner Beute. Schlägt die Registrierung
fehl, meldet er die Beute nicht: sie bleibt beim Agenten und zählt als
verloren. Sie geht nicht verloren — sie liegt weiter auf dem Zielsystem und
wird im nächsten Lauf erneut gefunden.

## Consequences

- **ADR-0001s Zusage stimmt jetzt.** Registrierung und Secret-Upload können
  nicht mehr auseinanderlaufen: der Server lässt es nicht zu. Die Prüfung
  gilt für jeden Client, auch für einen älteren Agenten, der die Reihenfolge
  nicht einhält.
- **Der Agent wird zuerst deployed.** Ein Server, der die Regel schon
  erzwingt, während ein alter Agent noch läuft, weist dessen Upload ab — der
  alte Agent verwirft den Fehler und meldet die Beute nicht. Die Beute
  bleibt zwar auf dem Zielsystem, der Lauf meldet aber Erfolg. Deshalb:
  erst der Agent, dann der Server.
- **Ein Lauf mit einem nicht registrierten Host scheitert sichtbar.** Der
  Upload antwortet mit 400, der Agent zählt den Fund als verloren und der
  Lauf endet mit Exit 1. Das ist die gewollte Härte: der Fehler taucht im
  Journal auf, statt stillschweigend eine halbe Beute zu hinterlassen.
- **Ein älterer Agent, der die Beute eines unbekannten Hosts meldet, verliert
  sie auf dem Server.** Sie bleibt auf dem Zielsystem und taucht im nächsten
  Lauf wieder auf, wenn der Host registriert werden konnte.
- **Die Regel kostet eine zusätzliche Abfrage je Upload.** Der Server prüft
  die Existenz des Hosts, bevor er die Zeile schreibt. Bei der Größe der
  Ablage ist das unerheblich.
- **Das Schema bekommt keinen Fremdschlüssel.** SQLite würde die Prüfung beim
  Schreiben erzwingen, aber eine bestehende Datenbank mit verwaisten Zeilen
  müsste migriert werden. Die Prüfung im Code ist für beide Fälle gleich und
  braucht keine Migration.
