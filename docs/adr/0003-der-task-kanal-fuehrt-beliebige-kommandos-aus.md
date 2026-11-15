ADR-0003: Der Task-Kanal führt beliebige Kommandos aus — das Bearer-Token ist die Grenze
Status: accepted
Date: 2026-11-15

## Context

Der Task-Kanal lässt den Operator Kommandos anlegen, die der Agent auf dem
Zielsystem ausführt (`sh -c` bzw. `cmd /C`) und deren Ausgabe zurückmeldet.
Damit ist der Kanal freie Codeausführung — auf einem C2-Server, dessen Token
jeden Aufrufer zum Vollzugriff befähigt.

Zwei Gegenmaßnahmen lagen auf dem Tisch:

- eine **Whitelist** definierter Kommandos (`whoami`, `ipconfig`, `systeminfo`, …)
- eine **Sandbox**, in der die Kommandos laufen (Container, chroot, Job-Objekt
  mit eingeschränkten Rechten)

Beide schränken die Mächtigkeit des C2 — und damit genau das, wofür ein C2 im
autorisierten Übungseinsatz gebaut wird. Eine Whitelist wäre zudem eine zweite
Quelle der Wahrheit: jedes neue Kommando müsste in ihr stehen, und eine Lücke in
der Liste (ein ungefilterter Shell-Metazeichen-Pfad, ein unerwartetes Werkzeug)
öffnet sie wieder. Die Sandbox wäre die stärkere Variante, ist aber
plattformabhängig und auf Windows eine eigene Baustelle.

Die Zeitgrenze von 300 s je Kommando bleibt unabhängig davon bestehen: sie
verhindert, dass ein hängendes Kommando den Agentenlauf blockiert.

## Decision

Der Task-Kanal bleibt frei. Das Bearer-Token ist die Grenze, nicht eine
Kommando-Whitelist.

Festgehalten am 2026-11-15 als bewusste Entscheidung des Maintainers, damit sie
bei jedem Review als Entscheidung gelesen wird und nicht als Versehen.

## Consequences

- Wer das Token hat, hat Root-äquivalente Rechte auf dem Agenten-Host. Das ist
  die Eigenschaft, die das Token in den Betriebshandbüchern und der
  Risiko-Tabelle führt — der Task-Kanal folgt derselben Sperre wie der Rest
  des C2.
- Der Kanal ist nicht für Produktivsysteme gedacht. Für einen Betrieb gehört der
  C2-Server in ein Übungsnetz oder abgeschaltet.
- Eine Whitelist wäre eine zweite Quelle der Wahrheit neben dem C2-Protokoll
  und stünde im Widerspruch zu ADR-0001: die erlaubten Kommandos lägen dann an
  zwei Stellen, dem Protokoll und der Liste.
- Soll der Kanal später eingegrenzt werden, ist die **Sandbox** der richtige
  Weg — sie greift, ohne eine Liste zu pflegen. Die Entscheidung gegen die
  Whitelist bleibt dann bestehen.
- Der Task-Kanal folgt dem Token. Wer ihn abschaltet, tut das an der
  Zugriffssperre, nicht am Agenten.
