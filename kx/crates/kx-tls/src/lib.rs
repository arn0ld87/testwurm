//! Kx-Tls: TLS-Infrastruktur für Kx (rustls-basiert).
//!
//! Bietet Server- und Client-TLS-Configuration mit selbstsignierten Zertifikaten
//! (rcgen) sowie PEM-Datei-Handling für bestehende Zertifikatspfade.

use std::sync::Arc;

use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair};
use rustls::server::ServerConfig;
use rustls::client::ClientConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use thiserror::Error;

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
    let mut params = CertificateParams::new(vec![cn.to_string()]);
    // 10 Jahre gültig für langfristige C2-Deployment.
    params.not_after = time::OffsetDateTime::now_utc()
        + time::Duration::days(3650);
    let key_pair = KeyPair::generate_for(&rcgen::KeyAlgorithm::RSA2048)
        .map_err(|e| TlsError::CertGen(e.to_string()))?;
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
    let root_store = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
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
