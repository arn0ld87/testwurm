---
id: ISSUE-12
title: C2-API ist nicht authentifiziert — jeder mit Netzzugang liest die Beute
status: done
priority: high
---

## Description

Kein einziger Handler des C2-Servers erzwingt die Authentifizierung. `auth.rs` implementiert den Bearer-Token-Check korrekt — die Funktion wird nur nie aufgerufen.

`crates/kx-server/src/auth.rs` definiert:

```rust
pub struct Authenticated;
impl<S> axum::extract::FromRequestParts<S> for Authenticated { /* … */ }
```

Aber kein Handler nimmt den Extractor als Parameter entgegen, und in `main.rs` wird weder eine Middleware noch ein `from_fn`-Layer eingehängt. Der Compiler sagt es beim Build:

```
warning: field `token` is never used           --> crates/kx-server/src/main.rs:63:5
warning: function `verify` is never used        --> crates/kx-server/src/auth.rs:16:8
warning: struct `Authenticated` is never constructed
```

**Empirisch bestätigt** (gegen einen laufenden Server mit dem ISSUE-1-Fix):

| Anfrage | Ergebnis |
|---|---|
| `GET /api/hosts` ohne `Authorization`-Header | **HTTP 200**, Hosts-Liste |
| `GET /api/hosts` mit falschem Token | **HTTP 200**, Hosts-Liste |
| `POST /api/register` ohne Token | **HTTP 201**, Host wird angelegt |

Der Token wird beim Start korrekt generiert und nach `KX_SERVER_TOKEN` gelegt — er schützt nichts. Betroffen sind **alle fünf Vertragspfade**: `/api/register`, `/api/heartbeat`, `/api/secrets` (POST und GET), `/api/hosts`, `/api/tasks`. Das Dashboard (`GET /`) ist ebenfalls ungeschützt, es liest das Token nur aus dem URL-Query-Parameter.

Das ist ein Widerspruch zur eigenen Dokumentation: `crates/kx-server/src/main.rs:5` beschreibt den Server als „Bearer-Token geschützt". Die Beute aller erbeuteten Hosts — inklusive Klartext-Passwörter und NT-Hashes — ist für jeden lesbar, der den Port erreicht.

Related: ISSUE-1, ISSUE-11

## Acceptance Criteria

- [x] Jede Anfrage an `/api/register`, `/api/heartbeat`, `/api/secrets`, `/api/hosts` und `/api/tasks` ohne korrektes Bearer-Token wird mit **HTTP 401** abgewiesen — verifiziert per Smoke-Test (`GET /api/hosts` ohne Token → HTTP 401)
- [x] Ein falscher Token wird ebenfalls mit 401 abgewiesen — verifiziert per Smoke-Test (`GET /api/hosts` mit falschem Token → HTTP 401)
- [x] Der Token wird nicht mehr im Klartext nach stderr geschrieben, sobald die Auth erzwungen wird — der Hinweis bleibt nur als Startmeldung ohne Wert (`main.rs:221`)
- [x] Das Dashboard wird geschützt **oder** es wird explizit als bewusst ungeschützt dokumentiert und nicht über das Token-Feld vorgetäuscht — das Dashboard bleibt offen und meldet sich über `POST /api/login` an; die Daten dahinter sind geschützt, das HTML ist es nicht
- [x] Ein Test belegt den 401 für jeden der fünf Pfade — mit und ohne Header, mit falschem Token (`main.rs:334`, `api_paths_require_a_valid_bearer_token`)
- [x] Der Compiler meldet keine unbenutzte `Auth`/`verify`/`Authenticated` mehr — die toten Typen wurden entfernt, übrig ist `verify_token` und die Middleware `require_auth`

## Technical Notes

- Betroffen: `crates/kx-server/src/main.rs` (Router, Handler), `crates/kx-server/src/auth.rs` (`verify`, `Authenticated`)
- Zwei Ansätze, die der Design-Entwurf (`design_draft.md`, Welle 1) gegeneinander abwägt:
  - **Extractor:** jeder Handler nimmt `Authenticated` als Parameter. Explizit und lokal lesbar, aber jede neue Route muss es von Hand mitnehmen — die Schutzlücke ist dann wieder da, sobald jemand eine Route vergisst.
  - **Middleware auf Router-Ebene:** `Router::new().layer(middleware::from_fn(check_auth))` schützt alle Routen automatisch, neue Routen sind per Konstruktion geschützt. Für eine Sicherheitseigenschaft ist das die robustere Variante.
- Das Dashboard (`GET /`) muss vom Auth-Layer ausgenommen werden, sonst kann es sein eigenes Token nicht prüfen — es liest es ja aus der URL. Entweder bewusst öffentlich, oder das Token wird per Header übergeben statt per Query-Parameter (was es ohnehin aus der URL in Logs und Browser-History entfernt).
- Der Token-Vergleich in `verify` ist zeitkonstant nötig, um Timing-Angriffe zu vermeiden — der aktuelle Vergleich über `==` ist dafür nicht ausreichend, sobald die Auth scharf geschaltet wird. Der Entwurf greift das auf.
- Reihenfolge: ISSUE-1 muss vor diesem Fix kommen, sonst lässt sich der Fix nicht empirisch testen — der Server startet ja nicht.
