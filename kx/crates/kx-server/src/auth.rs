//! Kx-Server Authentifizierung: statisches Bearer-Token.
//!
//! Einfache Token-Prüfung für Operator- und Agent-Zugriffe. Das Token wird
//! via Umgebungsvariable KX_SERVER_TOKEN oder als Argument übergeben.

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

/// Prüft das Authorization-Header-Format "Bearer <token>".
///
/// Der Vergleich ist constant-time: ein `==` auf Strings liefert bei
/// unterschiedlichem Präfix früh zurück und gibt damit Information über das
/// gesuchte Token preis.
pub fn verify(parts: &Parts, expected: &str) -> bool {
    match parts.headers.get(AUTHORIZATION) {
        Some(h) => h
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
            .unwrap_or(false),
        None => false,
    }
}

/// Middleware, die jede Anfrage ohne korrektes Bearer-Token abweist.
///
/// Sie wird per `route_layer` auf dem API-Router angebracht und schützt damit
/// alle dort registrierten Routen — auch die, die später hinzukommen.
///
/// Wichtig: `route_layer` (nicht `layer`) führt die Prüfung nur aus, wenn die
/// Anfrage überhaupt auf eine Route trifft. Sonst würde ein 404 zu einem 401
/// und damit verraten, ob ein Pfad existiert.
///
/// Der Token kommt aus dem `AppState` — nicht aus einer Environment-Variable.
/// Eine Environment-Variable ist prozessweit: jeder Test, der sie setzt,
/// wirkt auf alle anderen. Im State steht der Token genau dort, wo er
/// geprueft wird.
pub async fn require_auth(
    State(state): State<crate::AppState>,
    req: Request,
    next: Next,
) -> Response {
    let expected = state.token.as_str();
    let (parts, body) = req.into_parts();

    if verify(&parts, expected) {
        next.run(Request::from_parts(parts, body)).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "unauthorized: korrektes Bearer-Token erforderlich",
        )
            .into_response()
    }
}

/// Prüft ein Token ohne Header — für den Login-Endpunkt.
///
/// Constant-time, wie `verify`.
pub fn verify_token(candidate: &str, expected: &str) -> bool {
    constant_time_eq(candidate.as_bytes(), expected.as_bytes())
}

/// Vergleicht zwei Bytefolgen constant-time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Der Laengenvergleich ist nicht geheim — die Laenge des Tokens steht im
    // Klartext im Header. Er muss aber vor dem Inhaltsvergleich stehen, damit
    // der Inhaltsvergleich bei gleicher Laenge immer vollstaendig laeuft.
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
