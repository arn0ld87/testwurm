ADR-0001: C2-Antworttypen sind strikt, Request-Typen sind lenient
Status: accepted
Date: 2026-11-11

## Context

Der C2-Wire-Vertrag lag an fünf Stellen im Baum mit eigenen Feldlisten. Weil
`serde` unbekannte Felder stillschweigend ignoriert, brach eine Umbenennung
nicht laut, sondern veränderte die Operator-Ansicht unbemerkt: Der C2-Server
serialisierte `Task.result`, der CLI-Typ erwartete `Task.output` — und weil
`output` optional war, galt das als gelesen. `kx-cli tasks` zeigte deshalb nie
ein Ergebnis.

Die Strictness des Vertrags entscheidet damit über eine Richtung, in der
Datenverlust passieren kann, und über eine, in dem das nur Kompatibilität
kostet.

## Decision

Das Modul `kx_core::c2` ist die einzige Definition des C2-Protokolls.
Seine Type sind asymmetrisch streng:

- **Antworttypen** (`Host`, `ExfiltratedSecret`, `Task`) tragen
  `#[serde(deny_unknown_fields)]`. Sie werden vom Server erzeugt und vom Client
  gelesen; hier entsteht der Schaden, also bricht es hier laut.
- **Request-Typen** (`RegisterRequest`, `HeartbeatRequest`, `SecretUpload`) sind
  lenient. Sie werden vom Agenten erzeugt und vom Server gelesen; ein neuerer
  Agent darf ein zusätzliches Feld schicken, ohne einen älteren Server zu
  brechen.

Zusätzlich gilt: die Host-Kennung wird im Request mitgeliefert und vom Server
nicht mehr aus der IP abgeleitet. Registrierung und Secret-Upload können
dadurch nicht mehr auseinanderlaufen. Der Server lehnt eine leere `host_id`
mit 400 ab.

## Consequences

- Eine Umbenennung oder ein neues Feld in einem Antworttyp bricht die
  Deserialisierung, statt Daten stillschweigend zu verlieren. Das ist die
  gewünschte Härte — der Bug, den dieser Vertrag verhindert, war genau eine
  solche Umbenennung.
- Ein neuerer Agent mit einem zusätzlichen Feld funktioniert weiter gegen
  einen älteren Server. In der Gegenrichtung bricht ein neuerer Server einen
  älteren Client — dieser Fall ist aktenkundig und meldet sich laut, statt
  still zu scheitern.
- Die Kehrseite: additive Erweiterung eines Antwortfelds erfordert ein
  gleichzeitiges Update von Server und Client. Das ist der Preis dafür, dass
  ein stiller Datenverlust unmöglich ist.
- Die Datenbankzeile ist nicht mehr der Wire-Typ. `kx-server` hält
  `HostRow`/`SecretRow`/`TaskRow` ohne serde und wandelt sie über `From` in die
  Vertragstypen. Eine Änderung am Tabellen-Schema bricht den Wire-Vertrag
  nicht mehr und umgekehrt.
