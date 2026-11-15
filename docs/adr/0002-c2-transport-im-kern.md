ADR-0002: Der C2-Transport liegt im Kern, nicht in den Clients
Status: accepted
Date: 2026-11-15

## Context

ADR-0001 hat `kx_core::c2` zur einzigen Definition des C2-Protokolls gemacht —
für die *Typen und Pfade*. Die *Ausübung* des Protokolls lag an zwei Stellen:
`kx-agent::c2` und `kx-cli::client`. Beide bauten denselben TLS-Client über
`kx_tls::client_config_trusting`, trimmten dieselbe Basis-URL über
`trim_end_matches('/')`, setzten denselben `Authorization: Bearer`-Header und
bildeten denselben HTTP-Status auf einen Fehler ab. Jede Stelle hatte ihr
eigenes Fehler-Enum mit derselben Gestalt: `C2Error` (Agent) und `ApiError`
(CLI), beide mit `Tls`/`Http`/`Json`.

Die Doppelung war nicht harmlos. Eine Änderung an der Basis-URL-Bildung, am
Header oder an der Statusabfrage musste an zwei Orten gemacht werden, und
`kx-server/src/e2e_test.rs` baute seine Requests ein drittes Mal von Hand —
ohne TLS, ohne Headerprüfung, mit eigener Serialisierung. Der Test prüfte
damit nicht den Request, den der Agent wirklich schickt.

ADR-0001 hat die Definition an eine Stelle gezogen, die Ausübung aber nicht.
Genau diese Lücke erlaubte das Auseinanderlaufen: ein neuer Endpunktpfad
käme in `c2.rs` an, während `client.rs` weiter den alten baut — und nichts
bräche, weil beide Crates für sich übersetzbar bleiben.

## Decision

Der Transport des C2-Protokolls liegt in `kx_core::c2::transport`. Er umfasst
TLS-Aufbau, Bearer-Header, URL-Bildung, die Abbildung eines HTTP-Status auf
einen Fehler und die JSON-Serialisierung in beide Richtungen. Es gibt genau
einen Fehlertyp dafür: `TransportError` mit den Varianten `Tls`, `Http` und
`Json` — die Fehlermeldungen bleiben wortgleich.

`kx-agent::c2` und `kx-cli::client` sind dünne Adapter: sie binden die
Pfadkonstanten und die Protokolltypen an den Transport. Die CLI behält ihr
eigenes `ApiError`, aber nur noch für ihren Datei-I/O-Fehler beim Export;
Transportfehler werden durchgereicht.

Der Transport ist zweistufig gebaut: `build_request` und `post_json_request`
erzeugen den Request, ohne ihn zu schicken — das braucht nur den Token.
`Transport::send` schickt ihn über TLS. Der Server-Test nutzt die erste Stufe
und ruft den Router direkt auf; damit prüft er genau den Request, den der
Agent schickt.

## Consequences

- **`kx-core` ist nicht mehr HTTP-frei.** Das Crate hängt jetzt an `kx-tls`,
  `ureq` und `http`. Der Preis ist der Kern des Entscheids: ein Protokoll,
  dessen Definition und Ausübung auseinanderliegen, darf auseinanderlaufen.
  Der Kern bleibt asynchron-frei — der Transport ist blockierend, genau wie
  der `ureq`-Aufruf, den der Agent schon vorher synchron innerhalb seiner
  `async fn` ausführte.
- **Die Kante `kx-tls` → `kx-core` ist entfernt.** Sie existierte im Manifest,
  wurde im Quellcode aber nirgends benutzt. Ohne ihre Entfernung wäre die
  neue Kante `kx-core` → `kx-tls` ein Zyklus. `kx-tls` ist damit eine
  Basislage ohne interne Crate-Abhängigkeit.
- **Der Lockfile bleibt unberührt.** `http` 1.x, `ureq` 2.x und `kx-tls`
  waren bereits aufgelöst; es kommt keine zweite Version einer Krypto-Crate
  dazu. Geändert sind nur die Kanten zwischen den Workspace-Crates.
- **Die Bytes auf der Leitung bleiben dieselben.** Die Serialisierung läuft
  weiter über `serde_json::Value` und damit über eine `BTreeMap` — die
  Schlüssel stehen sortiert. Ein direktes `to_vec` über den Typ hätte die
  Felder in Deklarationsreihenfolge geschrieben: andere Bytes, gleiche
  Bedeutung.
- **Ein Fehlertyp weniger im Baum, einer mehr in der CLI.** `C2Error` ist
  weg; die CLI hat ihren Datei-I/O-Fehler behalten, weil der Export ihn
  braucht. Der Bedientext des Operators ändert sich nicht.
