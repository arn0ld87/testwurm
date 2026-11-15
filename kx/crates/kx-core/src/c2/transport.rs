//! Der Transport des C2-Protokolls — die Ausübung des Vertrags aus [`super`].
//!
//! [`super`] definiert die *Typen und Pfade* des Protokolls. Dieser Modul
//! definiert seine *Ausübung*: TLS-Aufbau, Bearer-Header, URL-Bildung und die
//! Abbildung eines HTTP-Status auf einen Fehler.
//!
//! Vorher stand diese Ausübung zweimal im Baum — in `kx-agent::c2` und in
//! `kx-cli::client`. Beide Stellen bauten denselben TLS-Client, trimmten
//! dieselbe Basis-URL, setzten denselben Authorization-Header und bildeten
//! denselben Status auf einen Fehler ab; jede hatte ihr eigenes Fehler-Enum
//! (`C2Error`, `ApiError`) mit derselben Gestalt. Der Agent und die CLI sind
//! jetzt dünne Adapter über diesen Transport.
//!
//! **Warum der Transport im Kern liegt.** ADR-0001 sagt: `kx_core::c2` ist
//! die einzige Definition des C2-Protokolls. Ein Protokoll, dessen Definition
//! und dessen Ausübung in zwei Crates liegen, erlaubt das Auseinanderlaufen:
//! ein neuer Pfad käme in `c2.rs` an, während `client.rs` weiter den alten
//! baut — und nichts bräche, weil beide für sich übersetzbar bleiben.
//!
//! Der Preis: `kx-core` hängt jetzt an `kx-tls` und `ureq` und ist damit
//! nicht mehr HTTP-frei. Der Kern bleibt asynchron-frei — der Transport ist
//! blockierend, genau wie der `ureq`-Aufruf, den der Agent schon heute
//! synchron innerhalb seiner `async fn` ausführt.
//!
//! **Der Aufbau ist zweistufig.** [`build_request`] und [`post_json_request`]
//! erzeugen den Request, ohne ihn zu schicken; das braucht nur den Token.
//! [`Transport::send`] schickt ihn, das braucht eine TLS-Verbindung. Der
//! Server-Test braucht nur die erste Stufe: er ruft den Router direkt auf.
//! Damit prüft er genau den Request, den der Agent schickt.

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

/// Der Fehler des C2-Transports.
///
/// Er ersetzt die beiden Fehler-Enums, die vorher an zwei Stellen standen und
/// dieselbe Gestalt hatten: `C2Error` im Agenten, `ApiError` in der CLI. Die
/// Meldungen sind unverändert — der Operator sieht dieselben Texte.
#[derive(Debug, Error)]
pub enum TransportError {
    /// TLS-Setup fehlgeschlagen.
    #[error("TLS-Setup fehlgeschlagen: {0}")]
    Tls(String),
    /// HTTP-Request fehlgeschlagen.
    #[error("HTTP-Request fehlgeschlagen: {0}")]
    Http(String),
    /// Antwort-JSON konnte nicht geparst werden.
    #[error("Antwort-JSON ungültig: {0}")]
    Json(String),
}

/// Baut einen C2-Request: Methode, Pfad, Bearer-Header und Body.
///
/// Das ist die Reinform des Transports — sie braucht keine Verbindung und
/// kennt den Server nicht. Der Pfad muss eine gültige URI sein; im Protokoll
/// sind es die `PATH_*`-Konstanten aus [`super`].
///
/// Ein Body setzt den Header `content-type: application/json`; ohne Body
/// trägt der Request keinen.
pub fn build_request(
    method: Method,
    path: &str,
    token: &str,
    body: Option<Vec<u8>>,
) -> Request<Vec<u8>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.unwrap_or_default())
        .expect("gültiger C2-Request")
}

/// Baut einen GET-Request.
pub fn get_request(path: &str, token: &str) -> Request<Vec<u8>> {
    build_request(Method::GET, path, token, None)
}

/// Baut einen POST-Request mit JSON-Body.
///
/// Die Serialisierung läuft bewusst über `serde_json::Value`: dessen Felder
/// sind eine `BTreeMap`, ihre Schlüssel stehen sortiert. Ein direktes
/// `to_vec` über den Typ würde die Felder in Deklarationsreihenfolge
/// schreiben — andere Bytes auf der Leitung, gleiche Bedeutung. So bleiben
/// die Bytes auf der Leitung dieselben wie vor dem Umzug des Transports.
pub fn post_json_request<T: Serialize>(
    path: &str,
    token: &str,
    body: &T,
) -> Result<Request<Vec<u8>>, TransportError> {
    let wert = serde_json::to_value(body).map_err(|e| TransportError::Json(e.to_string()))?;
    let bytes = serde_json::to_vec(&wert).map_err(|e| TransportError::Json(e.to_string()))?;
    Ok(build_request(Method::POST, path, token, Some(bytes)))
}

/// Liest eine JSON-Antwort.
pub fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, TransportError> {
    serde_json::from_slice(body).map_err(|e| TransportError::Json(e.to_string()))
}

/// Der C2-Transport: er baut die Requests und schickt sie über TLS.
///
/// Der Aufbau ist zweistufig, weil die beiden Hälften verschiedene
/// Voraussetzungen haben: das Bauen braucht nur den Token, das Schicken eine
/// TLS-Verbindung zum Server. Der Server-Test nimmt die erste Hälfte und ruft
/// den Router direkt auf — der Request, den er prüft, ist derselbe, den der
/// Agent schickt.
pub struct Transport {
    /// Der HTTP-Client, der ausschließlich dem Server-Zertifikat vertraut.
    agent: ureq::Agent,
    /// Die Basis-URL des Servers, ohne abschließenden Slash.
    base_url: String,
    /// Der Bearer-Token im Authorization-Header.
    token: String,
}

impl Transport {
    /// Baut einen Transport, der dem Server-Zertifikat `cert_pem` vertraut.
    ///
    /// `cert_pem` ist das PEM des Servers. Eine Verifikation gegen den
    /// System-Store ist nicht möglich, weil der Server selbstsignierte
    /// Zertifikate verwendet.
    pub fn new(server: &str, token: &str, cert_pem: &[u8]) -> Result<Self, TransportError> {
        let client_config = kx_tls::client_config_trusting(cert_pem)
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        Ok(Self {
            agent: ureq::AgentBuilder::new().tls_config(client_config).build(),
            base_url: server.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Baut einen Transport und liest das Server-Zertifikat von einer Datei.
    pub fn from_cert_file(
        server: &str,
        token: &str,
        cert_path: &str,
    ) -> Result<Self, TransportError> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| TransportError::Tls(format!("Zertifikat nicht lesbar: {e}")))?;
        Self::new(server, token, &cert_pem)
    }

    /// Die Basis-URL des Servers.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Schickt einen gebauten Request über TLS.
    ///
    /// Ein Status ab 400 ist ein Fehler — der HTTP-Client meldet ihn, bevor
    /// der Body gelesen wird. Der Fehlertext nennt deshalb die URL und den
    /// Status, nicht den Body.
    pub fn send(&self, request: &Request<Vec<u8>>) -> Result<ureq::Response, TransportError> {
        let url = format!("{}{}", self.base_url, request.uri().path());
        let mut ureq_request = self.agent.request(request.method().as_str(), &url);
        for (name, value) in request.headers() {
            let value = value
                .to_str()
                .map_err(|e| TransportError::Http(e.to_string()))?;
            ureq_request = ureq_request.set(name.as_str(), value);
        }
        let body = request.body();
        if body.is_empty() {
            ureq_request
                .call()
                .map_err(|e| TransportError::Http(e.to_string()))
        } else {
            ureq_request
                .send_bytes(body)
                .map_err(|e| TransportError::Http(e.to_string()))
        }
    }

    /// Schickt einen POST mit JSON-Body. 200 und 201 gelten als Erfolg.
    pub fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<(), TransportError> {
        let request = post_json_request(path, &self.token, body)?;
        let response = self.send(&request)?;
        ensure_ok(response).map(|_| ())
    }

    /// Schickt einen POST mit JSON-Body und liest die JSON-Antwort.
    pub fn post_json_response<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, TransportError> {
        let request = post_json_request(path, &self.token, body)?;
        let response = self.send(&request)?;
        let response = ensure_ok(response)?;
        let body = response
            .into_string()
            .map_err(|e| TransportError::Http(e.to_string()))?;
        parse_json(body.as_bytes())
    }

    /// Schickt einen GET und liest die JSON-Antwort.
    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, TransportError> {
        let request = get_request(path, &self.token);
        let response = self.send(&request)?;
        let body = response
            .into_string()
            .map_err(|e| TransportError::Http(e.to_string()))?;
        parse_json(body.as_bytes())
    }
}

/// Prüft den HTTP-Status; 200 und 201 gelten als Erfolg.
///
/// Der Fehler nennt den Status und den Body — der Body, weil er die
/// Ablehnung des Servers erklärt (leere `host_id`, falsches Token).
fn ensure_ok(response: ureq::Response) -> Result<ureq::Response, TransportError> {
    if response.status() == 200 || response.status() == 201 {
        Ok(response)
    } else {
        let status = response.status();
        let body = response.into_string().unwrap_or_else(|_| "<binär>".into());
        Err(TransportError::Http(format!("Status {status}: {body}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "kx-testzugang";

    /// Der Request trägt den Authorization-Header in genau der Form, die der
    /// Server prüft.
    #[test]
    fn der_request_traegt_den_bearer_header() {
        let request = get_request("/api/hosts", TOKEN);
        let header = request
            .headers()
            .get(AUTHORIZATION)
            .expect("Authorization-Header")
            .to_str()
            .expect("ASCII");
        assert_eq!(header, "Bearer kx-testzugang");
    }

    /// Ein GET trägt keinen Body und keinen Content-Type — sonst unterschiede
    /// sich der Request des Agenten von dem des Server-Tests.
    #[test]
    fn ein_get_trägt_keinen_body() {
        let request = get_request("/api/hosts", TOKEN);
        assert!(request.body().is_empty());
        assert!(request.headers().get(CONTENT_TYPE).is_none());
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), "/api/hosts");
    }

    /// Ein POST mit JSON-Body trägt den Content-Type und den serialisierten
    /// Body.
    #[test]
    fn ein_post_trägt_den_json_body() {
        let request = post_json_request("/api/register", TOKEN, &serde_json::json!({"a": 1}))
            .expect("serialisierbar");
        assert_eq!(request.method(), Method::POST);
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .expect("Content-Type-Header")
            .to_str()
            .expect("ASCII");
        assert_eq!(content_type, "application/json");
        assert_eq!(request.body().as_slice(), br#"{"a":1}"#);
    }

    /// Die Basis-URL wird getrimmt — ein abschließender Slash würde sonst
    /// einen doppelten Slash im Pfad erzeugen.
    #[test]
    fn die_basis_url_wird_getrimmt() {
        let transport = Transport::new("https://c2.local:8443/", TOKEN, &[]).expect("Transport");
        assert_eq!(transport.base_url(), "https://c2.local:8443");
    }
}
