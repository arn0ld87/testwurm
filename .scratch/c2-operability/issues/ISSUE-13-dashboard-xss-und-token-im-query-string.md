---
id: ISSUE-13
title: Dashboard rendert API-Werte ohne Escaping — gespeichertes XSS; Token steht im Query-String
status: done
priority: high
---

## Description

Zwei zusammenhängende Eigenschaften des C2-Dashboards:

**1. Stored XSS.** `kx-server/src/dashboard.rs:30-32` setzt die API-Werte per
`innerHTML` in die Tabelle, ohne sie zu escapen:

```js
document.querySelector('#'+id+' tbody').innerHTML =
  data.map(row => '<tr>' + map(row).join('') + '</tr>').join('');
...
load('/api/hosts', 'hosts', h => [h.ip, h.hostname, h.os, h.status].map(x => `<td>${x}</td>`));
```

Der Server legt die gelieferten Strings unverändert ab (`main.rs:73-86`, nur
`host_id` wird auf Leere geprüft). Damit ist der Pfad vom Angreifer bis zur
Ausführung im Browser des Operators offen.

Verifiziert am 2026-11-11 end-to-end gegen den laufenden Server:

```
POST /api/register  {"host_id":"10.0.0.5","ip":"10.0.0.5",
                     "hostname":"<img src=x onerror=alert(1)>","os":"Windows"}
→ HTTP 201

GET /api/hosts → HTTP 200
  body enthält:  <img src=x onerror=alert(1)>
```

Der Wert wird unescaped in `<td>${x}</td>` interpoliert und per `innerHTML`
gesetzt — er wird ausführbares Markup.

**2. Token im Query-String.** `dashboard.rs:27` liest das Token aus der URL:

```js
const TOKEN = new URLSearchParams(location.search).get('token') || '';
```

Damit landet das C2-Token in der Browser-Historie, in der Adressleiste, in den
Server-Logs und in jedem geteilten Dashboard-Link.

## Acceptance Criteria

- [x] API-Werte werden vor dem Einsetzen in die Tabelle escaped — `textContent`
      statt `innerHTML` oder ein `escapeHtml()`-Helper vor dem Zeilenaufbau —
      umgesetzt als `esc(s)` (`dashboard.rs:45`), das `& < > " '` escaped; alle
      drei Mapper laufen durch `esc(x)`
- [x] Das Dashboard holt das Token nicht aus dem Query-String, sondern über ein
      HTML-Login-Formular; das Token wird danach nur noch als
      `Authorization`-Header gesendet
- [x] Es landet kein Token in URL, Browser-Historie oder Server-Log
- [x] Ein Test belegt, dass ein Host mit HTML im `hostname` als Text und nicht
      als Markup erscheint (`dashboard.rs:264`, `dashboard_escapes_every_api_value`)
- [ ] Ein Test belegt, dass das Dashboard ohne Anmeldung keine Daten anzeigt —
      **noch offen**: sachlich erfüllt, weil die API ohne Token 401 liefert und
      das JavaScript erst nach dem Login lädt, aber es gibt dafür keinen
      eigenen Test. Der zugehörige Test `dashboard_does_not_read_the_token_from_the_url`
      deckt den Query-String ab

## Technical Notes

- Betroffen: `kx/crates/kx-server/src/dashboard.rs:27` (Token-Quelle) und
  `:30-32` (Escaping)
- Das Escaping ist **Vorbedingung** für die Login-Umstellung, nicht deren
  Anhang: sobald das Token im Arbeitsspeicher des Browsers liegt, kann ein
  injiziertes `<script>` es auslesen. Ohne Escaping verschlechtert die
  Umstellung die Lage, statt sie zu verbessern.
- Der Auth-Bypass (ISSUE-12) ist die Voraussetzung dafür, dass dieser Pfad
  überhaupt relevant wird: solange die API offen ist, kann jeder die Daten
  ohnehin abrufen. Wird ISSUE-12 behoben, ohne ISSUE-13 zu beheben, entsteht
  die Lücke erst dann für den Operator — der einzige Nutzer, der das
  Dashboard tatsächlich verwendet.
- Das Dashboard ist laut `kx-server/src/dashboard.rs:49` die fünfte Fundstelle
  des Wire-Vertrags — der Pfad steckt in einem JavaScript-String. Eine
  Änderung an den Feldnamen (etwa durch das Master-Key-Feld aus ISSUE-9)
  driftet hier unbemerkt; der Key-Set-Pinning-Test in `dashboard.rs` deckt das
  ab und muss mitgezogen werden.
- Das `?token=`-Muster sollte nicht durch eine neue Anmelde-Route mit
  Cookie ersetzt werden: Cookies werden vom Browser automatisch mitgesendet
  (CSRF), ein `Authorization`-Header nicht. Für ein Dashboard, das
  Credential-Passwörter anzeigt, ist das der gewichtigere Unterschied.
  Details in `design_draft.md`, Entscheidung D2.

Related: ISSUE-9
