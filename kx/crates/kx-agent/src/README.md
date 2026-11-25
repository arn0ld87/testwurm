# kx-agent src

## Overview

Quellmodulbaum des Binary-Crates `kx-agent`. `main.rs` ist der einzige
Entry-Point und erzeugt das Executable `kx-agent`; `c2.rs`, `datei.rs`,
`hostkey.rs`, `lauf.rs`, `meldung.rs`, `propagate.rs` und `tasks.rs` sind die Module
(`mod c2;`, `mod datei;`, `mod hostkey;`, `mod lauf;`, `mod meldung;`,
`mod propagate;`, `mod tasks;` in [main.rs:main]). Alle Module sind **private** —
`pub`-Symbole darin sind deshalb nur crate-intern erreichbar, das Crate stellt
keine Bibliotheks-API bereit [main.rs:mod c2] [main.rs:mod datei]
[main.rs:mod hostkey] [main.rs:mod lauf] [main.rs:mod meldung]
[main.rs:mod propagate] [main.rs:mod tasks].

`hostkey.rs` kapselt die Host-Master-Keys gegen den oeffentlichen
Server-Schluessel (Option `--server-key`): je Host ein eigener Master-Key, das
Passwort wird damit verschluesselt und der Klartext verlaesst den Agenten
nicht mehr [hostkey.rs:KeySealer] [hostkey.rs:schluessel_fuer].

`datei.rs` exfiltriert Dateien als KXENC-Container (Option `--exfil-file`,
Issue #31): lesen, mit dem Master-Key des Hosts versiegeln, den Container
**neben** das Original schreiben (`<name>.kxenc`) und an den C2 melden. Das
Original bleibt unangetastet; ohne `--server-key` geht keine Datei raus und
jede zählt als verloren [datei.rs:exfiltriere_dateien].

`lauf.rs` **besitzt die Reihenfolge des Laufs**: die eigene Beute melden, die
Dateien exfiltrieren (`--exfil-file`), die
Persistenz installieren, die Hosts entdecken (ARP-Sweep oder vorgegebene
`--hosts`-Liste), die Propagation ausfuehren, die Funde melden, die Tasks
abarbeiten. Vorher lag das in einer Funktion im Einstiegspunkt — der
verbindungsstärkste Knoten im Code-Graph, ohne Test. Die Abhängigkeiten werden
hineingereicht, nicht im Lauf erzeugt: der C2-Port, der Schlüsselvorrat, die
Umgebung, die Argumente. Damit lässt sich ein Lauf ohne Server, ohne Netz und
ohne Dateisystem prüfen [lauf.rs:Lauf] [lauf.rs:Lauf::start].

`main.rs` ist der Einstiegspunkt: Argumente parsen, Abhängigkeiten bauen, den
Lauf starten, den Exit-Code melden. `c2.rs` kapselt die HTTP-Kommunikation als
dünnen Adapter über den Transport aus `kx_core::c2::transport` (dort: ureq +
rustls via `kx_tls`), `propagate.rs` die Scan-und-Exploit-Logik (`kx_scanner`,
`kx_exploit`).

Der Wire-Vertrag liegt nicht in diesem Crate, sondern in `kx_core::c2` — Agent
und C2-Server sprechen denselben Vertrag [c2.rs:C2Client]. Das Crate definiert
deshalb **keine** eigenen Payload-Typen: der Port `C2Port` nimmt direkt
`kx_core::c2::RegisterRequest` und `kx_core::c2::SecretUpload` entgegen
[c2.rs:C2Port::registriere_host] [c2.rs:C2Port::melde_beute].

Der Meldeweg selbst liegt in `meldung.rs`: Reihenfolge, Zaehlung und
Verweigerung. `propagate.rs` **findet** und liefert Funde; `meldung.rs`
**meldet** [propagate.rs:run_propagation] [meldung.rs:melde].

Plattformabhängige Zugriffe (Secret-Extraktion, Persistenz) sind über
`#[cfg(target_os = "windows")]` bzw. `#[cfg(unix)]` getrennt
[lauf.rs:sammle_lokale_beute] [lauf.rs:System::install_persistenz].

## Interface

### main.rs — CLI und Einstiegspunkt

- `[main.rs:Args]` — crate-private Konfigurationsstruktur via `clap::Parser`,
  `#[command(name = "kx-agent", about = "Kx-autonomer Agent")]`. Argumente:
  `server` (`--server`, env `KX_C2_URL`), `token` (`--token`, env
  `KX_C2_TOKEN`, Typ `Secret` mit maskierter Debug-Ausgabe), `iface` (`--iface`,
  Default `eth0`), `start` (`--start`,
  Pflicht), `end` (`--end`, Pflicht), `own_ip` (`--own-ip`, Default
  `192.168.1.100`), `hosts` (`--hosts`, optional, kommagetrennt),
  `relay_script` (`--relay-script`, Default `assets/smbrelayx.py`), `server_cert`
  (`--server-cert`,
  Pflicht), `server_key` (`--server-key`, optional, JSON-Datei),
  `exfil_file` (`--exfil-file`, mehrfach angebbar, `Vec<PathBuf>`).
  Es existieren **keine** Subcommands.
- `[main.rs:main]` — `async fn main()` mit `#[tokio::main]`, einziger
  Prozess-Einstiegspunkt. Parst die Argumente, baut die Abhängigkeiten
  (Schlüsselvorrat, C2-Client, Umgebung), startet den Lauf und meldet den
  Exit-Code. Die **Reihenfolge** des Laufs liegt in `lauf.rs`, nicht hier.
- `[main.rs:Args::persistence_invocation]` — `fn persistence_invocation(&self, exe: PathBuf) -> Invocation`;
  die Flag-Liste existiert genau hier, sonst nirgends.

### lauf.rs — der Lauf

- `[lauf.rs:Umgebung]` — `pub trait Umgebung` mit drei Aufrufen:
  `lokale_beute()`, `funde_im_netz(entdeckt, relay_script)` und
  `install_persistenz(invocation)`. Das ist der Seam, an dem der Lauf vom
  System getrennt wird: im Betrieb die Extraktoren, die Angriffe und die
  Persistenz, im Test eine Attrappe, die feste Stücke liefert. Zwei Adapter —
  der Seam ist damit real [lauf.rs:Umgebung] [lauf.rs:System].
- `[lauf.rs:System]` — `pub struct System`; die Anbindung an `kx_win`,
  `kx_posix`, `kx_scanner` und `kx_exploit` [lauf.rs:System].
- `[lauf.rs:Lauf]` — `pub struct Lauf<'a, U: Umgebung>` mit den Feldern
  `args`, `port`, `sealer` und `umgebung`. Die Abhängigkeiten werden
  hineingereicht, nicht im Lauf erzeugt [lauf.rs:Lauf].
- `[lauf.rs:Lauf::new]` — `pub fn new(args, port, sealer, umgebung) -> Self` [lauf.rs:Lauf::new].
- `[lauf.rs:Lauf::start]` — `pub async fn start(&self) -> Ergebnis`; die
  Reihenfolge des Laufs. Liefert das Ergebnis der Meldungen; ob der Lauf ein
  Fehlschlag ist, entscheidet das Ergebnis selbst [lauf.rs:Lauf::start]
  [meldung.rs:Ergebnis::fehlgeschlagen].
- `[lauf.rs:sammle_lokale_beute]` — `async fn sammle_lokale_beute() -> Vec<Secret>`;
  plattformabhängige Extraktion via `kx_win::extract_lsass`,
  `kx_win::extract_credential_manager` (Windows) bzw.
  `kx_posix::extract_shadow_hashes`, `kx_posix::extract_aws_credentials` (unix).
  Das Versiegeln und das Melden liegen nicht hier, sondern in `meldung.rs`.
- `[lauf.rs:resolve_relay_script]` — `pub(crate) fn resolve_relay_script(script, basis) -> PathBuf`;
  sucht das Asset **neben dem Binary**, sonst bleibt der relative Pfad stehen.
- `[lauf.rs:binary_verzeichnis]` — `fn binary_verzeichnis() -> Option<PathBuf>` (privat).

### c2.rs — C2-Client

Der Client ist ein dünner Adapter über den Transport aus
`kx_core::c2::transport` — TLS-Aufbau, Bearer-Header, URL-Bildung und
Status→Fehler stehen dort, nicht in diesem Crate.

- `[c2.rs:C2Port]` — `pub trait C2Port` mit genau fünf Aufrufen:
  `registriere_host(&self, req: &RegisterRequest)`, `melde_beute(&self, upload: &SecretUpload)`,
  `hole_tasks(&self)`, `melde_task_ergebnis(&self, report: &TaskResultRequest)`
  und `melde_datei(&self, upload: &FileUpload)`.
  Das ist der Seam, an dem der Meldeweg und der Lauf testbar werden: hinter ihm
  stehen die `C2Client` im Betrieb und ein Aufzeichner im Test. Der Transport
  ist blockierend, die Methoden sind deshalb ehrlich synchron.
- `[c2.rs:C2Client]` — `pub struct C2Client` mit privatem Feld
  `transport: Transport`.
- `[c2.rs:C2Client::new]` — `pub fn new(server: &str, token: &str, server_cert: &str) -> Result<Self, TransportError>`;
  liest das Server-Zertifikat über `Transport::from_cert_file`.
- `[c2.rs:C2Client]` — implementiert `C2Port`; `registriere_host` POST
  `{base_url}/api/register`, `melde_beute` POST `{base_url}/api/secrets`,
  `hole_tasks` GET `{base_url}/api/tasks`, `melde_task_ergebnis` POST
  `{base_url}/api/tasks/result`, `melde_datei` POST `{base_url}/api/files`.

### datei.rs — Datei-Exfiltration (Issue #31)

- `[datei.rs:DateiBilanz]` — `pub struct DateiBilanz` mit `uebertragen` und
  `verloren`. Wie bei der Beute zählt die zugestellte Datei, nicht die
  vorbereitete.
- `[datei.rs:exfiltriere_dateien]` — `pub fn exfiltriere_dateien(port, sealer, host_id, pfade) -> DateiBilanz`;
  je Datei: lesen → `kx_core::kxenc::seal` → `<name>.kxenc` neben das Original
  → `melde_datei`. Ohne Server-Schlüssel gibt es keinen Container und keinen
  Klartext-Upload — jede Datei zählt als verloren. Ein Fehlschlag bricht die
  übrigen Dateien nicht ab. Der Upload trägt `sealed_master` mit (ADR-0005):
  die Datei bleibt auch nach einem neuen Agent-Lauf lesbar.

### meldung.rs — die Meldung an den C2

Das Modul besitzt die Reihenfolge, die Zählung und die Verweigerung. Es
erzeugt die Beute nicht — es meldet sie.

- `[meldung.rs:HostFund]` — `pub struct HostFund` mit `host_id: String`,
  `ip: String`, `os: Option<String>`, `status: String` und
  `secrets: Vec<Secret>`. Die Einheit ist der Host, nicht das Stück: Beute
  ohne Host ist für den Operator wertlos.
- `[meldung.rs:Ergebnis]` — `pub struct Ergebnis` mit den Zählern
  `hosts_registriert`, `hosts_verloren`, `beute_uebertragen`, `beute_verloren`,
  `beute_nicht_extrahiert`, `tasks_verloren`, `dateien_uebertragen`,
  `dateien_verloren` und dem Flag `persistenz_fehlgeschlagen`.
- `[meldung.rs:Ergebnis::c2_nicht_erreichbar]` — `pub fn c2_nicht_erreichbar(&self) -> bool`;
  kein Host kam an.
- `[meldung.rs:Ergebnis::fehlgeschlagen]` — `pub fn fehlgeschlagen(&self) -> bool`; jede verlorene
  Host-Anmeldung und jede verlorene Beute ist ein Fehlschlag.
  der C2 war nicht erreichbar, oder Beute ging verloren, die erbeutet war.
- `[meldung.rs:Ergebnis::zusammenfuehren]` — `pub fn zusammenfuehren(self, andere: Ergebnis) -> Ergebnis`;
  die Agent meldet in zwei Phasen, beide zählen in dieselbe Bilanz.
- `[meldung.rs:melde]` — `pub fn melde(port: &dyn C2Port, sealer: Option<&KeySealer>, funde: &[HostFund]) -> Ergebnis`;
  für jeden Fund: erst den Host registrieren, dann seine Beute melden. Schlägt
  die Registrierung fehl, wird die Beute **nicht** gemeldet und zählt als
  verloren.

### tasks.rs — Task-Ausführung

- `[tasks.rs:run_pending_tasks]` — `pub async fn run_pending_tasks(port: &dyn C2Port, host_id: &str) -> Result<usize, TransportError>`;
  holt die offenen Tasks, führt diejenigen mit eigener Host-Kennung und Status
  `pending` aus und meldet Status und Ausgabe zurück.
- `[tasks.rs:execute_command]` — `fn execute_command(command: &str) -> CommandOutput` (privat);
  führt das Kommando über die Shell aus (`sh -c` unter unix, `cmd /C` unter Windows) und
  sammelt stdout und stderr.
- `[tasks.rs:truncate]` — `fn truncate(text: &str, max_len: usize) -> String` (privat);
  kürzt die Ausgabe an einer Zeichengrenze, damit kein UTF-8-Zeichen zerrissen wird.

### propagate.rs — Scan und Exploit

- `[propagate.rs:run_propagation]` — `pub async fn run_propagation(discovered: &[DiscoveredHost], relay_script: &str) -> Vec<HostFund>`;
  nutzt `kx_scanner::scan_tcp`, `kx_exploit::smb_relay_dcsync`,
  `kx_exploit::try_default_credentials`. Liefert je Host einen Fund: der Host
  und das, was auf ihm erbeutet wurde. Die Wire-Typen entstehen erst beim
  Melden.
- `[propagate.rs:service_for_port]` — `fn service_for_port(port: u16) -> &'static str` (privat);
  festes Port-zu-Dienst-Mapping, deckungsgleich mit der Scanliste: 22 `ssh`,
  80 `http`, 135 `msrpc`, 443 `https`, 1433 `mssql`, 1521 `oracle`, 3306 `mysql`,
  3389 `rdp`, 445 `smb`, 5432 `postgres`, 5900 `vnc`, 8080 `http-proxy`, sonst
  `unknown`.

### Protokolltypen (aus `kx_core::c2`)

- `[kx-core/src/c2.rs:RegisterRequest](../../kx-core/src/c2.rs)` — `pub struct RegisterRequest`, Felder
  `host_id: String`, `ip: String`, `hostname: Option<String>`,
  `os: Option<String>`, `status: Option<String>`.
- `[kx-core/src/c2.rs:SecretUpload](../../kx-core/src/c2.rs)` — `pub struct SecretUpload`, Felder
  `host_id: String`, `cred_type: String`, `username: String`,
  `password: String`, `source: Option<String>`.
- `[kx-core/src/c2.rs:PATH_REGISTER](../../kx-core/src/c2.rs)` / `[kx-core/src/c2.rs:PATH_SECRETS](../../kx-core/src/c2.rs)`
  — die vom Client benutzten Pfadkonstanten `"/api/register"` und
  `"/api/secrets"`.
- `[kx-core/src/c2.rs:STATUS_DISCOVERED](../../kx-core/src/c2.rs)` /
  `[kx-core/src/c2.rs:STATUS_COMPROMISED](../../kx-core/src/c2.rs)` /
  `[kx-core/src/c2.rs:STATUS_AGENT](../../kx-core/src/c2.rs)` — die vom Agenten gesetzten
  Host-Status.

## Invariants

- Die Host-Kennung des Agenten ist seine eigene IP: `args.own_ip.to_string()`
  [lauf.rs:Lauf::host_kennung]. Eine Funktion `local_host_id` existiert im
  Crate **nicht**; die Kennung liegt im Lauf-Modul, nicht in `main.rs`.
- Der Agent meldet sich selbst **zusammen mit seiner Beute**: ein Fund, ein
  Aufruf. Das Melde-Modul registriert den Host und meldet danach seine Beute
  — die Reihenfolge liegt dort, nicht beim Aufrufer [meldung.rs:melde].
- Jeder Fund meldet **erst den Host, dann seine Beute**. Schlägt die
  Registrierung fehl, wird die Beute nicht gemeldet — sie bleibt beim Agenten
  und zählt als verloren [meldung.rs:melde].
- Jeder Master-Key entsteht je Host **einmal** für die ganze Laufzeit. Derselbe
  Schlüssel versiegelt die Beute des Hosts und geht als `sealed_master` bei
  seiner Registrierung mit [hostkey.rs:KeySealer::schluessel_fuer].
- Jedes lokal extrahierte Secret trägt die Host-Kennung des Agenten — der Host, bei dem es erbeutet wurde, ist hier der Agent selbst [lauf.rs:sammle_lokale_beute].
- Die Beuteaufnahme existiert genau einmal: `Secret` → versiegeln → `SecretUpload` liegt im Melde-Modul. `propagate.rs` und `main.rs` bauen den Upload nicht mehr selbst [meldung.rs:melde].
- Die Ziel-Host-Kennung reist im Upload mit und kann nicht mehr auseinanderlaufen: „Die Ziel-Host-Kennung steht im Upload selbst — sie kann nicht mehr auseinanderlaufen." [c2.rs:C2Port::melde_beute].
- `SecretUpload.host_id` muss auf einen registrierten Host verweisen; der Server lehnt eine leere Kennung ab [kx-core/src/c2.rs:SecretUpload](../../kx-core/src/c2.rs).
- Jeder Host wird **genau einmal** pro Propagationslauf registriert. Der Push liegt nach der Port-Schleife; vorher wurde er pro offenem Port gepusht, wodurch ein späterer Eintrag mit Status `discovered` den Status `compromised` überschrieb [propagate.rs:run_propagation].
- Der SMB-Relay-Zweig (Port 445) wird erreicht, wenn der Scan mit `kx_scanner::COMMON_PORTS` läuft und diese Liste 445 enthält — **ohne 445** — ist [propagate.rs:run_propagation] [kx-scanner/src/tcp_scan.rs:COMMON_PORTS](../../kx-scanner/src/tcp_scan.rs).
- Der Default-Credential-Zweig (Dienst `ssh`) liefert ein Secret, wenn `kx_exploit::try_default_credentials` eine Kombination bestätigt: die Funktion führt einen echten SSH-Versuch über `sshpass` durch und liefert `Ok(Some(Auth))`; ein Fehler oder eine abgelaufene Zeitgrenze lässt den Zweich leer, der Agent läuft weiter [propagate.rs:run_propagation] [kx-exploit/src/credential_stuff.rs:try_default_credentials](../../kx-exploit/src/credential_stuff.rs).
- Der Host-Status wird nur bei erfolgreichem Exploit von `discovered` auf `compromised` gehoben; der Fehlerpfad des SMB-Relay lässt ihn auf `discovered` [propagate.rs:run_propagation].
- Der unter unix geschriebene systemd-Unit startet das Binary mit allen
  Pflichtargumenten: `--server`, `--token`, `--server-cert`, `--iface`, `--start`,
  `--end`, `--own-ip` und `--relay-script`. Die Unit ist ein Einmal-Lauf
  (`Type=oneshot`, `Restart=no`) und setzt `WorkingDirectory` auf das
  Verzeichnis des Binaries — `Type=simple` mit `Restart=always` wäre eine
  Neustart-Schleife gewesen, weil `main()` linear endet
  [lauf.rs:Lauf::install_persistenz] [kx-posix/src/persist.rs:systemd_unit_content](../../kx-posix/src/persist.rs).
- Der Takt kommt nicht aus der Unit, sondern aus dem Timer
  (`kx-agent.timer`, `OnBootSec=2min`, `OnUnitActiveSec=5min`,
  `Persistent=true`); die Service-Unit hängt an ihm
  [kx-posix/src/persist.rs:systemd_timer_content](../../kx-posix/src/persist.rs).
- Der Pfad des Relay-Skripts wird **neben dem Binary** gesucht
  (`<binary-dir>/assets/smbrelayx.py`); gibt es das dort nicht, bleibt der
  relative Pfad stehen. Der persistierte Agent bekommt den aufgelösten
  Pfad fest in die Argumentliste eingetragen
  [lauf.rs:resolve_relay_script] [main.rs:Args::persistence_invocation].
- Das Token steht **nicht** im Klartext in der Unit-Datei: sie ist für jeden
  lesbar, der die Datei lesen darf. Die Unit referenziert `${KX_C2_TOKEN}`, das
  systemd aus der Environment-Datei `/etc/kx/kx-agent.env` (0600) auflöst
  [lauf.rs:Lauf::install_persistenz] [kx-posix/src/persist.rs:install_systemd_service](../../kx-posix/src/persist.rs).
- Der Agent arbeitet offene Tasks ab: nach den Funden holt
  `tasks::run_pending_tasks` die offenen Tasks des eigenen Hosts, führt jedes
  Kommando unter einer Zeitgrenze von 300 s aus und meldet das Ergebnis über
  `POST /api/tasks/result` zurück [lauf.rs:Lauf::start] [tasks.rs:run_pending_tasks].
- Ungültige IP-Konfiguration lehnt clap bei der Argumentübergabe ab (`Args`
  trägt `Ipv4Addr`-Felder); im Lauf selbst gibt es keinen `.expect`-Panic-Pfad
  für IPs [main.rs:Args] [lauf.rs:Lauf::host_kennung].
- Fehler der Secret-Extraktion werden **nicht** verschluckt: jeder Extraktor
  liefert ein `Result`, ein Fehlschlag landet in `LokaleBeute.fehler`, wird
  geloggt und als `beute_nicht_extrahiert` gezählt [lauf.rs:sammle] [lauf.rs:Lauf::start].
- Im `--hosts`-Zweig parst clap die kommagetrennte Liste in `Vec<Ipv4Addr>`; nicht parsebare Einträge werden bei der Argumentübergabe abgelehnt, nicht stillschweigend verworfen. Die erzeugten `DiscoveredHost` tragen `mac: [0; 6]` [main.rs:Args] [lauf.rs:Lauf::entdecken].
- Die MAC-Adresse für den ARP-Sweep kommt vom Interface (`kx_scanner::read_mac`), nicht aus einem Platzhalter — der Sweep antwortet sonst nicht [lauf.rs:Lauf::entdecken].
- Der Logfilter stammt aus `tracing_subscriber::EnvFilter::try_from_default_env()` (liest `RUST_LOG`) und fällt bei Fehlschlag auf `"info"` zurück [main.rs:main].
- `std::process::exit(1)` wird bei fehlgeschlagener C2-Client-Initialisierung und bei einer unbrauchbaren Server-Schlüssel-Datei ausgelöst. Ein fehlgeschlagener ARP-Sweep ist **kein** Exit-Pfad — der Agent klopft dann den Bereich ab [main.rs:main] [lauf.rs:Lauf::entdecken].
- `std::process::exit(1)` wird am Ende des Laufs ausgelöst, wenn **eine** Host-Anmeldung oder **eine** Beute verloren ging oder **eine** Quelle nicht extrahierbar war. Das umfasst die eigene Anmeldung des Agenten: der C2-Server kennt den Agenten sonst nicht. Ein gescheiterter Exploit ist **kein** Fehlschlag — nichts gefunden ist ein Ergebnis [meldung.rs:Ergebnis::fehlgeschlagen] [main.rs:main].
- Fehler beim Melden werden **nicht** verworfen: jeder fehlgeschlagene Upload und jede fehlgeschlagene Registrierung wird geloggt und gezählt. Der Zähler entscheidet über den Exit-Code [meldung.rs:melde].
- Ist ein Server-Schlüssel konfiguriert und schlägt die Kapselung für einen Host fehl, geht die Beute **nicht** im Klartext hinaus — sie bleibt beim Agenten und zählt als verloren. Ohne Server-Schlüssel geht die Beute im Klartext; das ist der dokumentierte Normalfall [meldung.rs:melde] [kx-core/src/exfil.rs:upload].
- Feste `cred_type`/`source`-Paare: Windows-LSASS nutzt `secret_type` mit Quelle `"lsass"`, Credential Manager nutzt `"credential_manager"` mit Quelle `"cmdkey"`; unix nutzt `"shadow"` mit Quelle `"/etc/shadow"` und `"aws"` mit Quelle `"~/.aws/credentials"` [lauf.rs:sammle_lokale_beute].
- Erbeutete Credentials werden mit festen Werten erfasst: SMB-Relay als `cred_type` `"nt_hash"` mit Quelle `"smb_relay"`, SSH-Default-Credentials als `cred_type` `"password"` mit Quelle `"default_creds"` [lauf.rs:sammle_lokale_beute] [propagate.rs:run_propagation].
- Der Servicename ist auf beiden Plattformen `"kx-agent"`; der Windows-Anzeigename ist `"Kx Agent"`, unix übergibt eine leere Beschreibung [lauf.rs:Lauf::install_persistenz].
- Eine leere `discovered`-Liste beendet die Propagation sofort ohne Scan (`debug!`-Log, leere Ergebnisse). Der TCP-Scan läuft immer mit `kx_scanner::COMMON_PORTS` und Timeout `1000` [propagate.rs:run_propagation].
- Das Port-zu-Dienst-Mapping ist fest; jeder nicht gelistete Port ergibt `"unknown"` [propagate.rs:service_for_port].
- `base_url` ist `server.trim_end_matches('/')`; nachgestellte Slashes werden entfernt, bevor Pfade angehängt werden [kx-core/src/c2/transport.rs:Transport::new](../../kx-core/src/c2/transport.rs).
- Das Server-Zertifikat wird per `std::fs::read(server_cert)` geladen; ein Lesefehler wird zu `TransportError::Tls("Zertifikat nicht lesbar: {e}")`, ein Fehler in `kx_tls::client_config_trusting` zu `TransportError::Tls`. Eine Verifikation gegen den System-Store findet nicht statt, da der Server selbstsignierte Zertifikate verwendet [kx-core/src/c2/transport.rs:Transport::from_cert_file](../../kx-core/src/c2/transport.rs).
- Nur Status 200 und 201 gelten als Erfolg; jeder andere Status erzeugt `TransportError::Http(format!("Status {status}: {body}"))` mit Response-Body, Fallback `"<binär>"` bei nicht lesbarem Body [kx-core/src/c2/transport.rs:ensure_ok](../../kx-core/src/c2/transport.rs).
- Der Request trägt immer den Header `Authorization: Bearer {token}`; der Body ist die `serde_json`-Serialisierung des übergebenen `RegisterRequest` bzw. `SecretUpload` [kx-core/src/c2/transport.rs:post_json_request](../../kx-core/src/c2/transport.rs).
- `Args` leitet `Debug` ab, das Token-Feld ist aber mit dem eigenen Typ `Secret` gekapselt: dessen `Debug`-Ausgabe maskiert den Wert (`***`), der Klartext ist nur über `Secret::as_str` erreichbar. Eine Debug-Ausgabe der Argumentstruktur enthält das Token damit nicht [main.rs:Secret] [main.rs:Args].

## Side Effects

- `[main.rs:Args]` — Liest die Umgebungsvariablen `KX_C2_URL` und `KX_C2_TOKEN` (clap-Attribut `env` an `--server` und `--token`).
- `[main.rs:main]` — Initialisiert einen globalen `tracing_subscriber::fmt`-Subscriber und schreibt damit Logausgabe; der Filter wird aus `RUST_LOG` gelesen.
- `[lauf.rs:Lauf::entdecken]` — Führt einen ARP-Sweep des konfigurierten Bereichs aus: `kx_scanner::arp_sweep(&args.iface, &range_start, &range_end, &own_ip, &own_mac)`; erzeugt Netzwerkverkehr auf dem genannten Interface.
- `[propagate.rs:run_propagation]` — Führt den TCP-Connect-Scan über `kx_scanner::scan_tcp(&ips, kx_scanner::COMMON_PORTS, 1000)` auf allen entdeckten IPs aus; je Host und Port wird eine Task gespawnt, die einen `TcpStream::connect` mit Timeout versucht [kx-scanner/src/tcp_scan.rs:scan_tcp](../../kx-scanner/src/tcp_scan.rs).
- `[lauf.rs:sammle_lokale_beute]` — Greift auf Credential-Material des lokalen Hosts zu: `kx_win::extract_lsass()` und `kx_win::extract_credential_manager()` (Windows), `kx_posix::extract_shadow_hashes()` und `kx_posix::extract_aws_credentials()` (unix).
- `[meldung.rs:melde]` — Meldet jeden Fund beim C2-Server an: erst den Host (`POST /api/register`, `host_id` = `ip` = eigene IP für den eigenen Host, Status `"agent"`), dann seine Beute (`POST /api/secrets`). Schlägt die Registrierung fehl, wird die Beute nicht gemeldet [meldung.rs:melde].
- `[hostkey.rs:KeySealer::schluessel_fuer]` — Kapselt je Host einmal für die ganze Laufzeit einen Master-Key gegen den öffentlichen Server-Schlüssel; der Key geht als `sealed_master` bei der Registrierung mit und versiegelt die Beute desselben Hosts [hostkey.rs:KeySealer::schluessel_fuer].
- `[meldung.rs:melde]` — Lädt jedes Stück Beute per `client.melde_beute(upload)` an den C2-Server hoch; Fehler je Stück werden geloggt und gezählt, die Schleife läuft weiter.
- `[meldung.rs:melde]` — Meldet alle propagierten Hosts und ihre Beute an den C2-Server; die Reihenfolge ist Host zuerst, Beute danach, die Rueckgabewerte werden nicht verworfen.
- `[lauf.rs:Lauf::install_persistenz]` — Liest den Pfad der eigenen Executable über `std::env::current_exe()`.
- `[lauf.rs:Lauf::install_persistenz]` — Installiert unter Windows den Run-Key via `kx_win::install_run_key`; unter unix zuerst `kx_posix::install_systemd_service`, bei einem Fehler `kx_posix::install_cron_service` (`@reboot`-Cron-Job als zweiter Weg, z.B. im Container ohne systemd). Erst wenn beide scheitern, zählt die Persistenz als fehlgeschlagen.
- `[lauf.rs:Lauf::install_persistenz]` — Schreibt unter unix die Unit-Datei `/etc/systemd/system/kx-agent.service`, die Timer-Datei `/etc/systemd/system/kx-agent.timer` und die Environment-Datei `/etc/kx/kx-agent.env` (0600, Verzeichnis 0700); jede Datei nur, wenn sich ihr Inhalt ändert. Führt `systemctl daemon-reload` (nur nach einer Änderung), `systemctl enable kx-agent` und `systemctl enable --now kx-agent.timer` aus [kx-posix/src/persist.rs:install_systemd_service](../../kx-posix/src/persist.rs).
- `[lauf.rs:resolve_relay_script]` — Prüft, ob der Assetpfad neben dem Binary liegt (`<binary-dir>/assets/smbrelayx.py`), und gibt sonst den relativen Pfad zurück; der persistierte Agent bekommt den aufgelösten Pfad in seiner Argumentliste.
- `[lauf.rs:Lauf::install_persistenz]` — Spawnt unter Windows `cmd.exe /C sc.exe create kx-agent binPath= "<exe>" start= auto DisplayName= "Kx Agent"` und danach `sc.exe start kx-agent` [kx-win/src/persist.rs:install_service](../../kx-win/src/persist.rs) [kx-win/src/persist.rs:start_service](../../kx-win/src/persist.rs).
- `[lauf.rs:sammle_lokale_beute]` — Liest unter unix `/etc/shadow` [kx-posix/src/secrets.rs:extract_shadow_hashes](../../kx-posix/src/secrets.rs) und `$HOME/.aws/credentials` (mit `HOME` als Env-Variable, Fallback `/root`) [kx-posix/src/secrets.rs:extract_aws_credentials](../../kx-posix/src/secrets.rs).
- `[lauf.rs:sammle_lokale_beute]` — Spawnt unter Windows `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ...` für den Credential Manager [kx-win/src/secrets.rs:extract_credential_manager](../../kx-win/src/secrets.rs) und `mimikatz.exe sekurlsa::logonpasswords` für LSASS [kx-win/src/secrets.rs:extract_lsass](../../kx-win/src/secrets.rs).
- `[c2.rs:C2Client::new]` — Liest das Server-Zertifikat (PEM) per `std::fs::read` von der Platte; der `ureq::Agent` des Transportes vertraut genau diesem PEM über `kx_tls::client_config_trusting` [kx-core/src/c2/transport.rs:Transport::from_cert_file](../../kx-core/src/c2/transport.rs).
- `[c2.rs:C2Port::registriere_host]` — Sendet einen HTTP-POST an `{base_url}/api/register` mit JSON-Body = serialisierter `RegisterRequest` und Header `Authorization: Bearer {token}`.
- `[c2.rs:C2Port::melde_beute]` — Sendet einen HTTP-POST an `{base_url}/api/secrets` mit JSON-Body = serialisierter `SecretUpload` und Header `Authorization: Bearer {token}`.
- `[propagate.rs:run_propagation]` — Versucht SMB-Relay nach DCSync gegen Hosts mit Port 445 über `kx_exploit::smb_relay_dcsync(&relay_cfg)` unter Verwendung des Pfads `relay_script`; fehlt das Skript oder Impacket, endet der Versuch kontrolliert mit einem Fehler.
- `[propagate.rs:run_propagation]` — Versucht einen SSH-Login mit Default-Credentials über `kx_exploit::try_default_credentials(&host_id, service)`; die Funktion startet je Kombination einen `sshpass`-Subprozess mit einer Zeitgrenze und bricht nach spätestens 60 s für alle Kombinationen ab [kx-exploit/src/credential_stuff.rs:try_default_credentials](../../kx-exploit/src/credential_stuff.rs).

## Verification

- Run: `cargo test` (ausgeführt in `/Volumes/T7/Projekte/testwurm/kx`)
- Stand: `cargo test --workspace` läuft grün — **130 Tests, 0 Fehler**; davon `cargo test -p kx-agent`: **16 Tests, 0 Fehler**, davon 3 in `c2.rs` (`client_uses_the_contract_paths`, `register_request_serializes_host_id`, `secret_upload_carries_its_host_id`).
- Die Tests prüfen die Vertragsbindung: `PATH_REGISTER == "/api/register"`, `PATH_SECRETS == "/api/secrets"`, die Serialisierung von `RegisterRequest` (`v["ip"]`, `v["host_id"]`) und von `SecretUpload` (`v["host_id"]`, `v["source"]`) [c2.rs:tests::client_uses_the_contract_paths] [c2.rs:tests::register_request_serializes_host_id] [c2.rs:tests::secret_upload_carries_its_host_id].
- Die AF_PACKET-spezifischen Teile von `kx-scanner/src/arp.rs` sind mit `#[cfg(target_os = "linux")]` ausgezeichnet; `arp_sweep` existiert in beiden Varianten und liefert außerhalb Linux `ScanError::Unsupported` statt zu kompilieren [kx-scanner/src/arp.rs:arp_sweep](../../kx-scanner/src/arp.rs).
