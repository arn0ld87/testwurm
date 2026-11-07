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
