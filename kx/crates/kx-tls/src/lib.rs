//! Kx-Tls: TLS-Infrastruktur für Kx (rustls-basiert).
//!
//! Bietet Server- und Client-TLS-Configuration mit selbstsignierten Zertifikaten
//! (rcgen) sowie PEM-Datei-Handling für bestehende Zertifikatspfade.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::client::ClientConfig;
use rustls::server::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use thiserror::Error;

/// Installiert den CryptoProvider für diesen Prozess.
///
/// Der Workspace aktiviert `rustls/ring`; ohne explizite Installation löst
/// rustls den Provider beim ersten `ServerConfig::builder()` auf. Solange genau
/// ein Provider im Feature-Set liegt, ist das eindeutig — aber die Auflösung
/// ist ein `panic!`, kein `Result`, und sie passiert an der Stelle, an der
/// jemand die TLS-Konfiguration baut.
///
/// Deshalb wird der Provider hier festgelegt: `kx-tls` ist der einzige Ort, an
/// dem TLS-Konfiguration entsteht, und er wird von Server, Agent und CLI
/// geteilt. Wer `kx-tls` benutzt, bekommt damit überall dasselbe Verhalten.
///
/// Ein zweiter Aufruf ist unschädlich: `install_default` liefert in dem Fall
/// einen Fehler, den wir als „bereits installiert" behandeln.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Fehlerarten der TLS-Infrastruktur.
#[derive(Debug, Error)]
pub enum TlsError {
    /// rcgen konnte kein Zertifikat erzeugen.
    #[error("Zertifikatserzeugung fehlgeschlagen: {0}")]
    CertGen(String),
    /// PEM-Datei konnte nicht gelesen oder geparst werden.
    #[error("PEM-Ladefehler: {0}")]
    PemLoad(String),
    /// rustls-Configuration konnte nicht aufgebaut werden.
    #[error("rustls-Config-Fehler: {0}")]
    Config(String),
}

/// Ein Server-TLS-Bündel: rustls-Config plus PEM-datiert.
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Erzeugt ein selbstsigniertes Zertifikat für die angegebene CN und
/// liefert eine rustls-ServerConfig sowie die PEM-Daten.
pub fn generate_server_tls(cn: &str) -> Result<ServerTls, TlsError> {
    install_crypto_provider();
    let mut params = CertificateParams::new(vec![cn.to_string()])
        .map_err(|e| TlsError::CertGen(e.to_string()))?;
    // 10 Jahre gültig für langfristige C2-Deployment.
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    let key_pair = KeyPair::generate().map_err(|e| TlsError::CertGen(e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::CertGen(e.to_string()))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let rustls_cert = CertificateDer::from(cert.der().to_vec());
    let rustls_key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], rustls_key)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    Ok(ServerTls {
        config: Arc::new(config),
        cert_pem: cert_pem.into_bytes(),
        key_pem: key_pem.into_bytes(),
    })
}

/// Client-TLS-Config, die dem selbstsignierten Server-Zertifikat vertraut.
/// `cert_pem` muss das PEM des Servers sein.
pub fn client_config_trusting(cert_pem: &[u8]) -> Result<Arc<ClientConfig>, TlsError> {
    install_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(cert_pem));
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::PemLoad(e.to_string()))?;
    for c in certs {
        root_store
            .add(c)
            .map_err(|e| TlsError::PemLoad(e.to_string()))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Lädt das Server-TLS-Bündel von der Platte — oder erzeugt es beim ersten Start.
///
/// Zertifikat **und** Schlüssel persistieren nebeneinander (Default neben der
/// Datenbank). Der Schlüssel bekommt dieselben Rechte wie die Datenbank: `0600`.
///
/// Warum auch der Schlüssel? TLS bindet das Zertifikat an sein Schlüsselpaar.
/// Ein beim Neustart frisch erzeugter Schlüssel zum alten Zertifikat scheitert
/// schon am `with_single_cert` — und der Agent, der das alte Zertifikat pinnt,
/// bekäme `BadSignature`. Nur ein persistiertes **Paar** übersteht den Neustart.
/// Die Issue #65 forderte „Schlüssel nie auf Platte"; das ist mit „Agent
/// übersteht Neustart" kryptografisch unvereinbar. Die Entscheidung samt
/// Begründung steht in ADR-0006. Der Schlüssel ist kein öffentliches Material,
/// aber die Datenbank neben ihm hält bereits die Beute — `0600` ist derselbe
/// Schutz.
///
/// Liegen beide Dateien, werden sie geladen. Fehlen beide, wird ein neues Paar
/// erzeugt und abgelegt. Liegt nur eine, ist der Zustand halbfertig: das wird
/// abgelehnt statt stillschweigend ein neues Paar zu erzeugen (das würde die
/// gepinnten Zertifikate aller Agenten brechen).
pub fn load_or_generate_server_tls(
    cn: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerTls, TlsError> {
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| TlsError::PemLoad(format!("{}: {e}", cert_path.display())))?;
            let key_pem = std::fs::read(key_path)
                .map_err(|e| TlsError::PemLoad(format!("{}: {e}", key_path.display())))?;
            let config = server_config_from_pem(&cert_pem, &key_pem)?;
            Ok(ServerTls {
                config,
                cert_pem,
                key_pem,
            })
        }
        (false, false) => {
            let tls = generate_server_tls(cn)?;
            write_private(cert_path, &tls.cert_pem)?;
            write_private(key_path, &tls.key_pem)?;
            Ok(tls)
        }
        _ => Err(TlsError::PemLoad(format!(
            "TLS-Material unvollständig: {} und {} müssen beide vorliegen oder beide fehlen",
            cert_path.display(),
            key_path.display()
        ))),
    }
}

/// Baut eine rustls-ServerConfig aus PEM-Zertifikat und PEM-Schlüssel.
fn server_config_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    install_crypto_provider();
    let mut cert_reader = std::io::BufReader::new(std::io::Cursor::new(cert_pem));
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::PemLoad(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::PemLoad("keine Zertifikate im PEM".into()));
    }
    let mut key_reader = std::io::BufReader::new(std::io::Cursor::new(key_pem));
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::PemLoad(e.to_string()))?
        .ok_or_else(|| TlsError::PemLoad("kein privater Schlüssel im PEM".into()))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Schreibt eine Datei atomar mit `0600` (Unix): erst eine temporäre Datei,
/// Rechte setzen, dann umbenennen. Der Schlüssel ist so zu keinem Zeitpunkt
/// für andere lesbar.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), TlsError> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    std::fs::write(&tmp, bytes)
        .map_err(|e| TlsError::PemLoad(format!("{}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| TlsError::PemLoad(format!("Rechte {}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| TlsError::PemLoad(format!("{}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ZAEHLER: AtomicU64 = AtomicU64::new(0);

    /// Ein eigenes Verzeichnis je Test — keine Kollision, kein tempfile-Dep.
    fn verzeichnis() -> PathBuf {
        let n = ZAEHLER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("kx-tls-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("Verzeichnis");
        dir
    }

    /// Der Neustart-Fall aus Issue #65: Zertifikat ablegen, neu laden —
    /// es ist dasselbe Paar, nicht ein frisch erzeugtes.
    #[test]
    fn das_zertifikat_uebersteht_einen_neustart() {
        let dir = verzeichnis();
        let cert = dir.join("kx-server.crt");
        let key = dir.join("kx-server.key");

        let erster = load_or_generate_server_tls("kx.local", &cert, &key).expect("erster Start");
        assert!(
            cert.exists() && key.exists(),
            "das Paar wurde nicht abgelegt"
        );

        // Ein zweiter Start liest von der Platte — er erzeugt nicht neu.
        let zweiter = load_or_generate_server_tls("kx.local", &cert, &key).expect("Neustart");
        assert_eq!(
            erster.cert_pem, zweiter.cert_pem,
            "das Zertifikat hat sich beim Neustart geändert"
        );
        assert_eq!(
            erster.key_pem, zweiter.key_pem,
            "der Schlüssel hat sich beim Neustart geändert"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ein Agent, der das Zertifikat des ersten Starts pinnt, kommt über den
    /// Neustart hinweg: der Handshake gegen die geladene Config gelingt.
    ///
    /// Das ist die Wirkung, die #65 verlangt — nicht nur „Datei ist gleich",
    /// sondern „die Verbindung steht noch". Ohne persistierten Schlüssel wäre
    /// dieser Handshake `BadSignature`.
    #[test]
    fn ein_gepinnter_agent_uebersteht_den_neustart() {
        let dir = verzeichnis();
        let cert = dir.join("kx-server.crt");
        let key = dir.join("kx-server.key");

        let erster = load_or_generate_server_tls("kx.local", &cert, &key).expect("erster Start");
        // Der Agent pinnt das Zertifikat des ersten Starts.
        let client_config = client_config_trusting(&erster.cert_pem).expect("Client-Config");

        // Der Server startet neu und lädt dasselbe Paar von der Platte.
        let zweiter = load_or_generate_server_tls("kx.local", &cert, &key).expect("Neustart");

        assert!(
            handshake_gelingt(&client_config, &zweiter.config, "kx.local"),
            "der gepinnte Agent scheitert am Neustart — BadSignature?"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Treibt einen rustls-Handshake zwischen Client und Server im Speicher.
    fn handshake_gelingt(
        client_config: &Arc<ClientConfig>,
        server_config: &Arc<ServerConfig>,
        name: &str,
    ) -> bool {
        use rustls::{ClientConnection, ServerConnection};
        use rustls_pki_types::ServerName;
        let server_name = ServerName::try_from(name.to_string()).expect("ServerName");
        let mut client = ClientConnection::new(client_config.clone(), server_name).expect("Client");
        let mut server = ServerConnection::new(server_config.clone()).expect("Server");

        // Beide Seiten pumpen, bis der Handshake durch ist. Ein Fehler auf
        // einer Seite (z. B. BadSignature) bricht ab und liefert false.
        for _ in 0..64 {
            if !client.is_handshaking() && !server.is_handshaking() {
                return true;
            }
            let mut buf = Vec::new();
            if client.wants_write() {
                if client.write_tls(&mut buf).is_err() {
                    return false;
                }
                let mut cursor = std::io::Cursor::new(&buf);
                if server.read_tls(&mut cursor).is_err() {
                    return false;
                }
                if server.process_new_packets().is_err() {
                    return false;
                }
            }
            buf.clear();
            if server.wants_write() {
                if server.write_tls(&mut buf).is_err() {
                    return false;
                }
                let mut cursor = std::io::Cursor::new(&buf);
                if client.read_tls(&mut cursor).is_err() {
                    return false;
                }
                if client.process_new_packets().is_err() {
                    return false;
                }
            }
        }
        !client.is_handshaking() && !server.is_handshaking()
    }

    /// Ohne Dateien wird ein neues Paar erzeugt und abgelegt.
    #[test]
    fn ohne_dateien_wird_ein_neues_paar_erzeugt() {
        let dir = verzeichnis();
        let cert = dir.join("kx-server.crt");
        let key = dir.join("kx-server.key");
        assert!(!cert.exists() && !key.exists());

        let tls = load_or_generate_server_tls("kx.local", &cert, &key).expect("Erzeugung");
        assert!(!tls.cert_pem.is_empty());
        assert!(cert.exists() && key.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Der Schlüssel liegt mit `0600` — wie die Datenbank neben ihm.
    #[cfg(unix)]
    #[test]
    fn der_schluessel_lieg_mit_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = verzeichnis();
        let cert = dir.join("kx-server.crt");
        let key = dir.join("kx-server.key");
        load_or_generate_server_tls("kx.local", &cert, &key).expect("Erzeugung");

        let mode = std::fs::metadata(&key)
            .expect("Metadaten")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "der Schlüssel ist zu offen: {:o}",
            mode & 0o777
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ein halbfertiger Zustand (nur Zertifikat, kein Schlüssel) wird abgelehnt
    /// statt stillschweigend ein neues Paar zu erzeugen.
    #[test]
    fn ein_halbfertiger_zustand_wird_abgelehnt() {
        let dir = verzeichnis();
        let cert = dir.join("kx-server.crt");
        let key = dir.join("kx-server.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\n").expect("Datei");

        let err = load_or_generate_server_tls("kx.local", &cert, &key);
        assert!(
            err.is_err(),
            "ein halbes Paar darf nicht stillschweigend rotieren"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
