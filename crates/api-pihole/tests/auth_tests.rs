mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use helpers::auth::{ADMIN_PASSWORD, APP_PASSWORD, TOTP_CODE};
use helpers::ftl::{self, assert_ftl_shape};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

/// Sends `request` to a clone of `app` and returns the status and JSON body
/// (`Value::Null` for an empty body).
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("request failed");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("invalid JSON")
    };
    (status, json)
}

fn post_auth(body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("failed to build request")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("failed to build request")
}

fn get_with_header(uri: &str, header: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header, value)
        .body(Body::empty())
        .expect("failed to build request")
}

fn post_auth_with_sid(body: Value, sid: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth")
        .header("content-type", "application/json")
        .header("X-FTL-SID", sid)
        .body(Body::from(body.to_string()))
        .expect("failed to build request")
}

fn delete_auth(sid: Option<&str>) -> Request<Body> {
    let builder = Request::builder().method("DELETE").uri("/auth");
    let builder = match sid {
        Some(sid) => builder.header("X-FTL-SID", sid),
        None => builder,
    };
    builder
        .body(Body::empty())
        .expect("failed to build request")
}

/// FTL's session object, checked against the mirror; `csrf` is only sent
/// with a valid session (auth.c `get_session_object`).
fn assert_session_reply(json: &Value, has_session: bool) {
    assert_ftl_shape::<ftl::AuthSession>(json);
    assert_eq!(
        json["session"].get("csrf").is_some(),
        has_session,
        "csrf must be sent only with a valid session: {json}"
    );
}

/// Logs in with `password` and returns the session id.
async fn login(app: &Router, password: &str) -> String {
    let (status, json) = send(app, post_auth(serde_json::json!({ "password": password }))).await;
    assert_eq!(status, StatusCode::OK, "login failed: {json}");
    json["session"]["sid"]
        .as_str()
        .expect("sid must be a string")
        .to_string()
}

async fn auth_app(totp_enrolled: bool) -> Router {
    let pool = helpers::create_test_db().await;
    helpers::create_pihole_test_app_with_auth(pool, totp_enrolled).await
}

#[tokio::test]
async fn get_auth_returns_unauthenticated_session_when_no_active_session() {
    let app = auth_app(false).await;

    let (status, json) = send(&app, get("/auth")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["totp"], false);
    assert!(json["session"]["sid"].is_null());
    assert_eq!(json["session"]["validity"], -1);
    assert_eq!(json["session"]["message"], "no SID provided");
}

#[tokio::test]
async fn get_auth_with_an_unknown_sid_is_unauthorized() {
    let app = auth_app(false).await;

    let (status, json) = send(&app, get_with_header("/auth", "X-FTL-SID", "not-a-session")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["valid"], false);
    assert!(json["session"]["sid"].is_null());
    assert_eq!(json["session"]["message"], "session unknown");
}

#[tokio::test]
async fn get_auth_reflects_a_valid_session() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let (status, json) = send(&app, get_with_header("/auth", "X-FTL-SID", &sid)).await;

    assert_eq!(status, StatusCode::OK);
    assert_session_reply(&json, true);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["sid"], sid.as_str());
    assert!(json["session"]["validity"].as_i64().unwrap() > 0);
    assert_eq!(json["session"]["message"], "correct password");
}

#[tokio::test]
async fn get_auth_answers_like_a_pihole_without_password_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = send(&app, get("/auth")).await;

    assert_eq!(status, StatusCode::OK);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["totp"], false);
    assert_eq!(json["session"]["message"], "no password set");
}

/// FTL's `totp` says whether the server has a second factor set up, in every
/// session object, not whether this login used one.
#[tokio::test]
async fn every_session_reply_reports_an_enrolled_second_factor() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": APP_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["session"]["totp"], true, "app-password login: {json}");
    let sid = json["session"]["sid"].as_str().expect("sid").to_string();

    let (_, json) = send(&app, get_with_header("/auth", "X-FTL-SID", &sid)).await;
    assert_eq!(json["session"]["totp"], true, "GET with a session: {json}");

    let (_, json) = send(&app, get("/auth")).await;
    assert_eq!(
        json["session"]["totp"], true,
        "GET without a session: {json}"
    );

    let (_, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": "wrong-password" })),
    )
    .await;
    assert_eq!(json["session"]["totp"], true, "wrong password: {json}");
}

#[tokio::test]
async fn login_with_correct_password_returns_session() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["message"], "password correct");
    let sid = json["session"]["sid"].as_str().expect("sid must be string");
    assert!(!sid.is_empty(), "sid must be non-empty on successful login");
    assert_eq!(json["session"]["validity"], 24 * 3600);
}

/// `cli/src/wiring/pihole_state.rs` built the state without a `LoginUseCase`,
/// which made `POST /auth` hand out a session for any password even though
/// `[auth]` is enabled.
#[tokio::test]
async fn login_rejects_wrong_password_when_auth_is_enabled() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": "anything-at-all" })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["message"], "password incorrect");
    assert!(json["session"]["sid"].is_null());
}

#[tokio::test]
async fn wrong_password_reply_is_ftls_session_object() {
    let app = auth_app(false).await;

    let (_, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": "wrong-password" })),
    )
    .await;

    assert_session_reply(&json, false);
}

#[tokio::test]
async fn login_reply_is_ftls_session_object() {
    let app = auth_app(false).await;

    let (_, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    assert_session_reply(&json, true);
}

#[tokio::test]
async fn login_without_a_password_is_a_bad_request() {
    let app = auth_app(false).await;

    let (status, json) = send(&app, post_auth(serde_json::json!({ "totp": 123456 }))).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"]["key"], "bad_request");
    assert_eq!(
        json["error"]["message"],
        "No password found in JSON payload"
    );
}

/// auth.c checks for the `password` key before it looks at the session.
#[tokio::test]
async fn login_without_a_password_is_a_bad_request_even_with_a_valid_sid() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let (status, json) = send(&app, post_auth_with_sid(serde_json::json!({}), &sid)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json["error"]["message"],
        "No password found in JSON payload"
    );
}

#[tokio::test]
async fn login_with_an_empty_password_and_a_valid_sid_returns_the_session() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let (status, json) = send(
        &app,
        post_auth_with_sid(serde_json::json!({ "password": "" }), &sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_session_reply(&json, true);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["sid"], sid.as_str());
    assert_eq!(json["session"]["message"], "correct password");
}

#[tokio::test]
async fn login_with_an_empty_password_and_no_session_is_unauthorized() {
    let app = auth_app(false).await;

    let (status, json) = send(&app, post_auth(serde_json::json!({ "password": "" }))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["message"], "password incorrect");
}

#[tokio::test]
async fn auth_response_schema_contains_all_required_pihole_v6_session_fields() {
    let app = auth_app(false).await;

    let (_, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    let session = &json["session"];
    assert!(
        session["valid"].is_boolean(),
        "session.valid must be boolean"
    );
    assert!(session["totp"].is_boolean(), "session.totp must be boolean");
    assert!(session["sid"].is_string(), "session.sid must be string");
    assert!(
        session.get("csrf").is_some(),
        "session.csrf must be present"
    );
    assert!(
        session["validity"].is_number(),
        "session.validity must be number"
    );
    assert!(
        session["message"].is_string(),
        "session.message must be string"
    );
}

#[tokio::test]
async fn login_answers_like_a_pihole_without_password_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": "anything" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["valid"], true);
    assert!(json["session"]["sid"].is_null());
    assert_eq!(json["session"]["validity"], -1);
    assert_eq!(json["session"]["message"], "no password set");
}

#[tokio::test]
async fn login_without_a_password_is_a_bad_request_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = send(&app, post_auth(serde_json::json!({}))).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json["error"]["message"],
        "No password found in JSON payload"
    );
}

#[tokio::test]
async fn login_with_api_token_as_app_password_returns_session() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": APP_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["session"]["message"], "app-password correct");
    let sid = json["session"]["sid"].as_str().expect("sid must be string");
    let (status, _) = send(&app, get_with_header("/stats/summary", "X-FTL-SID", sid)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn app_password_skips_the_second_factor() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": APP_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["session"]["valid"], true);
}

#[tokio::test]
async fn login_with_totp_enrolled_requires_the_code() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"]["key"], "bad_request");
}

#[tokio::test]
async fn login_with_totp_code_as_number_returns_session() {
    let app = auth_app(true).await;
    let code: u32 = TOTP_CODE.parse().unwrap();

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD, "totp": code })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["totp"], true);
}

#[tokio::test]
async fn login_with_wrong_totp_code_is_unauthorized() {
    let app = auth_app(true).await;

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD, "totp": "000000" })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["key"], "unauthorized");
}

/// A wrong password is tried as an app password too; that second check must
/// not count again, or the configured five attempts would shrink to three.
#[tokio::test]
async fn each_wrong_password_counts_once_toward_the_lockout() {
    let app = auth_app(false).await;
    let wrong = serde_json::json!({ "password": "wrong-password" });

    for attempt in 1..=5 {
        let (status, _) = send(&app, post_auth(wrong.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
    }

    let (status, json) = send(
        &app,
        post_auth(serde_json::json!({ "password": ADMIN_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["error"]["key"], "rate_limiting");
}

/// With no password there is no session to end: auth.c answers 401 with the
/// no-password session object.
#[tokio::test]
async fn logout_answers_like_a_pihole_without_password_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = send(&app, delete_auth(None)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["valid"], true);
    assert_eq!(json["session"]["message"], "no password set");
}

#[tokio::test]
async fn logout_invalidates_the_session() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let request = Request::builder()
        .method("DELETE")
        .uri("/auth")
        .header("X-FTL-SID", &sid)
        .body(Body::empty())
        .expect("failed to build request");
    let (status, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, get_with_header("/stats/summary", "X-FTL-SID", &sid)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_without_a_session_is_unauthorized() {
    let app = auth_app(false).await;

    let request = Request::builder()
        .method("DELETE")
        .uri("/auth")
        .body(Body::empty())
        .expect("failed to build request");
    let (status, json) = send(&app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["message"], "no SID provided");
}

fn delete_with_sid(uri: &str, sid: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("X-FTL-SID", sid)
        .body(Body::empty())
        .expect("failed to build request")
}

/// The `/auth/sessions` list as seen through `sid`.
async fn list_sessions(app: &Router, sid: &str) -> Vec<ftl::SessionEntry> {
    let (status, json) = send(app, get_with_header("/auth/sessions", "X-FTL-SID", sid)).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_ftl_shape::<ftl::AuthSessions>(&json).sessions
}

#[tokio::test]
async fn sessions_lists_every_live_session_and_marks_the_presented_one() {
    let app = auth_app(false).await;
    let first = login(&app, ADMIN_PASSWORD).await;
    login(&app, APP_PASSWORD).await;

    let sessions = list_sessions(&app, &first).await;

    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions.iter().filter(|s| s.current_session).count(), 1);
    for session in &sessions {
        assert!(session.valid);
        assert!(session.valid_until > session.login_at);
        assert!(session.last_active >= session.login_at);
    }
    let ids: std::collections::HashSet<i64> = sessions.iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), 2, "ids must tell the sessions apart");
}

#[tokio::test]
async fn deleting_a_session_by_its_id_ends_only_that_session() {
    let app = auth_app(false).await;
    let mine = login(&app, ADMIN_PASSWORD).await;
    let other = login(&app, ADMIN_PASSWORD).await;
    let other_id = list_sessions(&app, &mine)
        .await
        .into_iter()
        .find(|s| !s.current_session)
        .expect("the other session")
        .id;

    let (status, _) = send(
        &app,
        delete_with_sid(&format!("/auth/session/{other_id}"), &mine),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, get_with_header("/stats/summary", "X-FTL-SID", &other)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(&app, get_with_header("/stats/summary", "X-FTL-SID", &mine)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn deleting_a_session_id_that_names_none_is_a_bad_request() {
    // auth.c api_auth_session_delete.
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    for (id, message) in [
        ("abc", "Missing or invalid session ID"),
        ("-5", "Session ID out of bounds"),
        ("12345", "Session ID not in use"),
    ] {
        let (status, json) = send(&app, delete_with_sid(&format!("/auth/session/{id}"), &sid)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "id {id}");
        let reply = assert_ftl_shape::<ftl::ErrorReply>(&json);
        assert_eq!(reply.error.key, "bad_request");
        assert_eq!(reply.error.message, message, "id {id}");
    }
}

#[tokio::test]
async fn sessions_routes_need_a_session() {
    let app = auth_app(false).await;

    let (status, _) = send(&app, get("/auth/sessions")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let request = Request::builder()
        .method("DELETE")
        .uri("/auth/session/1")
        .body(Body::empty())
        .expect("failed to build request");
    let (status, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_with_an_unknown_sid_is_unauthorized() {
    let app = auth_app(false).await;

    let (status, json) = send(&app, delete_auth(Some("not-a-session"))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_session_reply(&json, false);
    assert_eq!(json["session"]["message"], "session unknown");
}

#[tokio::test]
async fn protected_routes_reject_requests_without_a_session() {
    let cases = [
        ("POST", "/action/gravity", None),
        ("POST", "/action/flush/logs", None),
        ("GET", "/queries", None),
        ("GET", "/stats/summary", None),
        ("GET", "/lists", None),
        ("GET", "/padd", None),
        ("GET", "/endpoints", None),
        (
            "POST",
            "/dns/blocking",
            Some(serde_json::json!({ "blocking": false })),
        ),
        (
            "POST",
            "/domains/deny/exact",
            Some(serde_json::json!({ "domain": "example.com" })),
        ),
    ];

    let mut open = Vec::new();
    for (method, uri, body) in cases {
        let app = auth_app(false).await;

        let body = body.map_or_else(Body::empty, |json| Body::from(json.to_string()));
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body)
            .expect("failed to build request");
        let (status, _) = send(&app, request).await;

        if status != StatusCode::UNAUTHORIZED {
            open.push(format!("{method} {uri} -> {status}"));
        }
    }

    assert!(
        open.is_empty(),
        "routes served without a session: {open:#?}"
    );
}

#[tokio::test]
async fn protected_route_rejects_unknown_session() {
    let app = auth_app(false).await;

    let (status, json) = send(
        &app,
        get_with_header("/stats/summary", "X-FTL-SID", "not-a-session"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"]["key"], "unauthorized");
}

#[tokio::test]
async fn protected_route_accepts_every_pihole_sid_carrier() {
    let app = auth_app(false).await;
    let sid = login(&app, ADMIN_PASSWORD).await;

    let requests = [
        get_with_header("/stats/summary", "X-FTL-SID", &sid),
        get_with_header("/stats/summary", "sid", &sid),
        get(&format!("/stats/summary?sid={sid}")),
    ];
    for request in requests {
        let uri = request.uri().clone();
        let headers = request.headers().clone();
        let (status, _) = send(&app, request).await;
        assert_eq!(status, StatusCode::OK, "{uri} {headers:?}");
    }
}

#[tokio::test]
async fn protected_routes_are_open_when_auth_is_disabled() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, _) = send(&app, get("/stats/summary")).await;

    assert_eq!(status, StatusCode::OK);
}
