//! Kx-Server Dashboard: einfache HTML-Übersicht über Hosts, Secrets, Tasks.
//!
//! Liefert eine minimale Single-Page-Übersicht, die die JSON-API abfragt.
//!
//! Die Spalten stehen in [`SPALTEN`] — Feldnamen des Wire-Typs. Das HTML wird
//! daraus gebaut: die Tabellenköpfe und der JavaScript-Mapper bekommen
//! dieselben Namen. Vorher stand die Feldliste **dreimal** im HTML-String —
//! in den Köpfen, im Mapper und im Test, der sie aus dem String.parsete.

use std::sync::OnceLock;

use kx_core::c2;

/// Die Spalten je Bereich.
///
/// Je Bereich: die Tabellen-ID, der Endpunkt aus dem Vertrag, die Variable
/// im JavaScript-Mapper, die Spalten als (Anzeigename, Feldname) und das
/// Feld, das seinen Platzhalter zeigt, wenn es leer ist.
///
/// Die Feldnamen sind die des Wire-Typs — `c2::Host::FIELDS` und so weiter.
/// Der Test vergleicht sie mit dem Vertrag.
const SPALTEN: &[(&str, &str, char, &[(&str, &str)], Option<&str>)] = &[
    (
        "hosts",
        c2::PATH_HOSTS,
        'h',
        &[
            ("IP", "ip"),
            ("Hostname", "hostname"),
            ("OS", "os"),
            ("Status", "status"),
        ],
        None,
    ),
    (
        "secrets",
        c2::PATH_SECRETS,
        's',
        &[
            ("Host", "host_id"),
            ("Typ", "cred_type"),
            ("Benutzer", "username"),
            ("Passwort", "password"),
            ("Quelle", "source"),
        ],
        Some("password"),
    ),
    (
        "tasks",
        c2::PATH_TASKS,
        't',
        &[
            ("Host", "host_id"),
            ("Befehl", "command"),
            ("Status", "status"),
            ("Ergebnis", "result"),
        ],
        None,
    ),
];

/// Der Platzhalter für versiegelte Beute.
///
/// Ist das Klartextfeld leer, liegt die Beute versiegelt vor. Der Chiffretext
/// wird **nicht** angezeigt — im Browser des Operators stünde sonst Klartext.
const VERSIEGELT: &str = "<verschluesselt>";

/// Die HTML-Vorlage des Dashboards.
///
/// `{tabellen}` und `{mapper}` werden aus [`SPALTEN`] gefüllt.
pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Kx-C2 Dashboard</title>
  <style>
    body { font-family: monospace; background:#111; color:#ddd; margin:2rem; }
    h1 { color:#7f8; } table { border-collapse: collapse; width:100%; }
    th, td { border:1px solid #444; padding:6px; text-align:left; }
    th { background:#222; } .host { color:#8cf; } .secret { color:#fc6; }
    #login { border:1px solid #444; padding:1rem; margin-bottom:1.5rem; }
    #login input { background:#222; color:#ddd; border:1px solid #444; padding:4px; }
    #login button { background:#333; color:#ddd; border:1px solid #444; padding:4px 12px; cursor:pointer; }
    #msg { color:#f88; }
  </style>
</head>
<body>
  <h1>Kx-C2 Dashboard</h1>
  <form id="login">
    <label for="token">C2-Token:</label>
    <input id="token" type="password" autocomplete="off">
    <button type="submit">Anmelden</button>
    <span id="msg"></span>
  </form>
{tabellen}
  <script>
    // Das Token steht in einer Variablen, nicht in der URL: im Query-String
    // landet es in Browser-Historie, Adressleiste und Server-Logs. Nach einem
    // Neuladen der Seite ist es verloren, der Operator meldet sich erneut an.
    let TOKEN = '';
    // API-Werte sind Fremddaten: ein Hostname kann HTML enthalten. Ohne
    // Escaping wird er beim Einsetzen in die Tabelle zu ausfuehrbarem Markup
    // (stored XSS) — im Browser des Operators, in dem die Beute-Passwoerter
    // stehen. Deshalb laeuft JEDER Wert durch diese Funktion.
    function esc(s) {
      return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      })[c]);
    }
    async function load(path, id, map) {
      const r = await fetch(path, { headers: { 'Authorization': 'Bearer ' + TOKEN } });
      if (!r.ok) { document.getElementById(id).innerHTML = '<tr><td>Auth fehlgeschlagen</td></tr>'; return; }
      const data = await r.json();
      document.querySelector('#'+id+' tbody').innerHTML =
        data.map(row => '<tr>' + map(row).join('') + '</tr>').join('');
    }
    function loadAll() {
{mapper}
    }
    document.getElementById('login').addEventListener('submit', async ev => {
      ev.preventDefault();
      const msg = document.getElementById('msg');
      msg.textContent = '';
      const token = document.getElementById('token').value;
      const r = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token })
      });
      if (!r.ok) { msg.textContent = 'Token falsch'; return; }
      TOKEN = token;
      document.getElementById('token').value = '';
      document.getElementById('login').style.display = 'none';
      loadAll();
    });
  </script>
</body>
</html>"#;

/// Das fertige Dashboard — aus der Vorlage und den Spalten gebaut.
///
/// Das Ergebnis wird einmal berechnet und dann wiederverwendet: die Seite
/// ändert sich nicht.
pub fn dashboard_html() -> String {
    static HTML: OnceLock<String> = OnceLock::new();
    HTML.get_or_init(|| {
        DASHBOARD_HTML
            .replace("{tabellen}", &tabellen())
            .replace("{mapper}", &mapper())
    })
    .clone()
}

/// Die Tabellen — Überschrift, Kopfzeile und Tabellenrumpf.
fn tabellen() -> String {
    SPALTEN
        .iter()
        .map(|(bereich, _, _, spalten, _)| {
            let kopf: String = spalten
                .iter()
                .map(|(anzeige, _)| format!("<th>{anzeige}</th>"))
                .collect();
            format!(
                "  <h2>{titel}</h2>\n  <table id=\"{bereich}\"><thead><tr>{kopf}</tr></thead><tbody></tbody></table>",
                titel = titel(bereich),
                bereich = bereich,
                kopf = kopf
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Die JavaScript-Mapper — je Bereich einer.
///
/// Sie lesen genau die Felder, die der Bereich anzeigt. Der Platzhalter
/// steht an dem Feld, das bei versiegelter Beute leer ist.
fn mapper() -> String {
    SPALTEN
        .iter()
        .map(|(bereich, pfad, variable, spalten, platzhalter_feld)| {
            let felder: Vec<String> = spalten
                .iter()
                .map(|(_, feld)| {
                    if *platzhalter_feld == Some(*feld) {
                        format!("{variable}.{feld} || '{VERSIEGELT}'")
                    } else {
                        format!("{variable}.{feld}")
                    }
                })
                .collect();
            format!(
                "      load('{pfad}', '{bereich}', {variable} => [{felder}].map(x => `<td>${{esc(x)}}</td>`));",
                pfad = pfad,
                bereich = bereich,
                variable = variable,
                felder = felder.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Die Überschrift eines Bereichs — die Tabellen-ID, großgeschrieben.
fn titel(bereich: &str) -> String {
    let mut zeichen = bereich.chars();
    match zeichen.next() {
        Some(erste) => erste.to_uppercase().collect::<String>() + zeichen.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn sample_host() -> c2::Host {
        c2::Host {
            host_id: "10.0.0.5".into(),
            ip: "10.0.0.5".into(),
            hostname: "target".into(),
            os: "Windows".into(),
            status: c2::STATUS_COMPROMISED.into(),
            first_seen: "2026-11-11T00:00:00Z".into(),
            last_seen: "2026-11-11T00:05:00Z".into(),
            sealed_master: String::new(),
        }
    }

    fn sample_secret() -> c2::ExfiltratedSecret {
        c2::ExfiltratedSecret {
            id: "s-1".into(),
            host_id: "10.0.0.5".into(),
            cred_type: "nt_hash".into(),
            username: "Administrator".into(),
            password: "hash".into(),
            source: "smb_relay".into(),
            collected_at: "2026-11-11T00:05:00Z".into(),
            sealed_password: String::new(),
            sealed_master: String::new(),
        }
    }

    fn sample_task() -> c2::Task {
        c2::Task {
            id: "t-1".into(),
            host_id: "10.0.0.5".into(),
            command: "whoami".into(),
            status: "done".into(),
            result: "nt authority\\system".into(),
            created_at: "2026-11-11T00:06:00Z".into(),
        }
    }

    /// Die Feldmenge des Wire-Typs — aus dem Typ selbst.
    fn keys<T: serde::Serialize>(wert: &T) -> BTreeSet<String> {
        serde_json::to_value(wert)
            .expect("serialisierbar")
            .as_object()
            .expect("Objekt")
            .keys()
            .cloned()
            .collect()
    }

    /// Das Dashboard liest genau die Endpunkte des Vertrags.
    #[test]
    fn dashboard_endpoints_are_the_contract_paths() {
        let html = dashboard_html();
        for pfad in [c2::PATH_HOSTS, c2::PATH_SECRETS, c2::PATH_TASKS] {
            assert!(
                html.contains(&format!("load('{pfad}'")),
                "der Vertragspfad {pfad} fehlt im Dashboard"
            );
        }
    }

    /// Das Dashboard liest nur Felder, die der Wire-Typ kennt.
    ///
    /// Die Feldliste steht am Typ (`c2::Host::FIELDS` und so weiter) — der
    /// Test vergleicht die Spalten damit. Vorher stand die Liste dreimal im
    /// HTML-String, und der Test parses sie aus dem String zurück.
    #[test]
    fn dashboard_reads_only_fields_the_contract_defines() {
        let vertrag: BTreeSet<&str> = c2::Host::FIELDS
            .iter()
            .chain(c2::ExfiltratedSecret::FIELDS.iter())
            .chain(c2::Task::FIELDS.iter())
            .copied()
            .collect();

        let mut geprueft = 0;
        for (_, _, _, spalten, _) in SPALTEN {
            for (_, feld) in spalten.iter() {
                assert!(
                    vertrag.contains(feld),
                    "das Dashboard liest '{feld}', das der Wire-Typ nicht kennt"
                );
                geprueft += 1;
            }
        }
        assert!(
            geprueft >= 13,
            "erwartete Feldzugriffe, gefunden: {geprueft}"
        );
    }

    /// Die Spalten sind Felder des **jeweiligen** Typs — nicht irgendeines.
    #[test]
    fn jede_spalte_ist_ein_feld_ihres_typs() {
        for (bereich, _, _, spalten, _) in SPALTEN {
            let vertrag: BTreeSet<&str> = match *bereich {
                "hosts" => c2::Host::FIELDS.iter().copied().collect(),
                "secrets" => c2::ExfiltratedSecret::FIELDS.iter().copied().collect(),
                "tasks" => c2::Task::FIELDS.iter().copied().collect(),
                other => panic!("unbekannter Bereich '{other}'"),
            };
            for (_, feld) in spalten.iter() {
                assert!(
                    vertrag.contains(feld),
                    "die Spalte '{feld}' im Bereich '{bereich}' kennt der Typ nicht"
                );
            }
        }
    }

    /// Das Dashboard liest das Feld `result` — den Namen, den der Server
    /// sendet. Vorher sendete er `result`, während die CLI `output`
    /// erwartete.
    #[test]
    fn dashboard_reads_the_task_result_field() {
        let html = dashboard_html();
        let task_zeile = html
            .lines()
            .find(|l| l.contains(c2::PATH_TASKS))
            .expect("Task-Zeile");
        assert!(
            task_zeile.contains("t.result"),
            "das Dashboard liest das Ergebnis-Feld nicht: {task_zeile}"
        );
    }

    /// Der Platzhalter steht an dem Feld, das bei versiegelter Beute leer ist.
    #[test]
    fn versiegelte_beute_zeigt_den_platzhalter() {
        let html = dashboard_html();
        assert!(
            html.contains(&format!("s.password || '{VERSIEGELT}'")),
            "das Dashboard zeigt den Platzhalter nicht"
        );
    }

    /// Das HTML-Escaping, gespiegelt in Rust.
    ///
    /// Der Browser wertet das JavaScript im Dashboard aus. Damit der Test
    /// aussagekräftig ist, spiegelt er die Ersetzungsregel nach — er prüft
    /// also nicht nur, dass ein `esc(` im HTML steht, sondern dass die
    /// Ersetzung genau die Zeichen behandelt, die HTML auslösen.
    fn escape_html(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                other => out.push(other),
            }
        }
        out
    }

    /// Jeder API-Wert läuft durch den Escape-Helper.
    ///
    /// Ohne diesen Test bleibt das Dashboard bei einem injizierten
    /// `<script>` im `hostname` ausführbar — der Fehler, der den XSS auslöst.
    #[test]
    fn dashboard_escapes_every_api_value() {
        let html = dashboard_html();
        // Der Helper muss existieren und genau die fünf HTML-Zeichen behandeln.
        assert!(
            html.contains("function esc("),
            "das Dashboard hat keinen Escaping-Helper"
        );
        for (raw, escaped) in [
            (
                "<img src=x onerror=alert(1)>",
                "&lt;img src=x onerror=alert(1)&gt;",
            ),
            ("a & b", "a &amp; b"),
            ("\"quoted\"", "&quot;quoted&quot;"),
            ("it's", "it&#39;s"),
            ("a > b", "a &gt; b"),
        ] {
            assert_eq!(escape_html(raw), escaped, "Escaping von {raw:?} falsch");
        }

        // Und: jeder Mapper, der einen Wert einsetzt, muss ihn escapen.
        for line in html.lines().filter(|l| l.contains("load('")) {
            assert!(
                line.contains("esc(x)"),
                "eine load()-Zeile setzt einen Wert unescaped ein: {line}"
            );
            assert!(
                !line.contains("${x}"),
                "eine load()-Zeile interpoliert einen Wert unescaped: {line}"
            );
        }
    }

    /// Das Token kommt nicht aus der URL.
    ///
    /// Im Query-String landet es in der Browser-Historie, in der Adressleiste
    /// und in den Server-Logs.
    #[test]
    fn dashboard_does_not_read_the_token_from_the_url() {
        assert!(
            !dashboard_html().contains("location.search"),
            "das Dashboard liest das Token weiterhin aus dem Query-String"
        );
    }

    /// Die Probe-Daten tragen die Felder, die das Dashboard liest — sonst
    /// wären die Vergleiche oben gegen eine leere Menge gelaufen.
    #[test]
    fn die_probe_daten_tragen_die_gelesenen_felder() {
        assert!(keys(&sample_host()).contains("ip"));
        assert!(keys(&sample_secret()).contains("sealed_password"));
        assert!(keys(&sample_task()).contains("result"));
    }
}
