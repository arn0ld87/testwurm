//! Kx-Server Authentifizierung: statisches Bearer-Token.
//!
//! Einfache Token-Prüfung für Operator- und Agent-Zugriffe. Das Token wird
//! via Umgebungsvariable KX_SERVER_TOKEN oder als Argument übergeben.

use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

/// Auth-Kontext, der das erwartete Token trägt.
#[derive(Clone)]
pub struct Auth {
    pub token: String,
}

/// Prüft das Authorization-Header-Format "Bearer <token>".
pub fn verify(parts: &Parts, expected: &str) -> bool {
    match parts.headers.get(AUTHORIZATION) {
        Some(h) => h
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == expected)
            .unwrap_or(false),
        None => false,
    }
}

/// Axum-Extension für authentizierte Requests.
#[derive(Clone)]
pub struct Authenticated;

impl<S> axum::extract::FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
{
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if verify(parts, std::env::var("KX_SERVER_TOKEN").unwrap_or_default().as_str()) {
            Ok(Authenticated)
        } else {
            Err(axum::http::StatusCode::UNAUTHORIZED)
        }
    }
}
