mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_application::ports::{PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_application::use_cases::LoginUseCase;
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, User, UserRole, UserSource};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Lightweight auth mocks for LoginUseCase integration
// ---------------------------------------------------------------------------

struct TestUserProvider {
    admin: User,
}

#[async_trait::async_trait]
impl UserProvider for TestUserProvider {
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        if username == self.admin.username.as_ref() {
            Ok(Some(self.admin.clone()))
        } else {
            Ok(None)
        }
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        Ok(vec![self.admin.clone()])
    }
    async fn update_password(&self, _: &str, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

struct TestPasswordHasher;

impl PasswordHasher for TestPasswordHasher {
    fn hash(&self, _: &str) -> Result<String, DomainError> {
        Ok("$hashed$".to_string())
    }
    fn verify(&self, password: &str, _: &str) -> Result<bool, DomainError> {
        Ok(password == "correct-password")
    }
}

struct InMemorySessionRepo {
    sessions: tokio::sync::Mutex<Vec<AuthSession>>,
}

impl InMemorySessionRepo {
    fn new() -> Self {
        Self {
            sessions: tokio::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl SessionRepository for InMemorySessionRepo {
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError> {
        self.sessions.lock().await.push(session.clone());
        Ok(())
    }
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        Ok(self
            .sessions
            .lock()
            .await
            .iter()
            .find(|s| s.id.as_ref() == id)
            .cloned())
    }
    async fn update_last_seen(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, id: &str) -> Result<(), DomainError> {
        self.sessions.lock().await.retain(|s| s.id.as_ref() != id);
        Ok(())
    }
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(self.sessions.lock().await.clone())
    }
}

fn build_login_use_case() -> Arc<LoginUseCase> {
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: User {
            id: Some(1),
            username: Arc::from("admin"),
            display_name: None,
            password_hash: Arc::from("$hashed$"),
            role: UserRole::Admin,
            source: UserSource::Toml,
            enabled: true,
            created_at: None,
            updated_at: None,
        },
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepo::new());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestPasswordHasher);
    let config = Arc::new(AuthConfig {
        enabled: true,
        session_ttl_hours: 24,
        ..AuthConfig::default()
    });
    Arc::new(LoginUseCase::new(
        user_provider,
        session_repo,
        hasher,
        config,
    ))
}

// ---------------------------------------------------------------------------
// GET /auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_auth_returns_unauthenticated_session_when_no_active_session() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("invalid JSON");

    assert!(
        json["session"].is_object(),
        "response must have a 'session' field"
    );
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["totp"], false);
    assert!(
        json["session"]["sid"]
            .as_str()
            .unwrap_or("nonempty")
            .is_empty(),
        "sid must be empty for unauthenticated session"
    );
    assert!(
        json["session"]["validity"].as_i64().unwrap_or(1) == 0,
        "validity must be 0 for unauthenticated session"
    );
}

// ---------------------------------------------------------------------------
// POST /auth — no LoginUseCase wired → open access
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_succeeds_when_no_login_use_case_is_wired() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "password": "anything-at-all" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert_eq!(
        json["session"]["valid"], true,
        "any password should be accepted when no LoginUseCase is wired"
    );
    let sid = json["session"]["sid"]
        .as_str()
        .expect("sid must be a string");
    assert!(!sid.is_empty(), "sid must be non-empty on successful login");
}

// ---------------------------------------------------------------------------
// DELETE /auth — logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_returns_no_content() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// Pi-hole v6 schema conformance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_response_schema_contains_all_required_pihole_v6_session_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "password": "any" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let session = &json["session"];
    assert!(
        session["valid"].is_boolean(),
        "session.valid must be boolean"
    );
    assert!(session["totp"].is_boolean(), "session.totp must be boolean");
    assert!(session["sid"].is_string(), "session.sid must be string");
    assert!(session["csrf"].is_string(), "session.csrf must be string");
    assert!(
        session["validity"].is_number(),
        "session.validity must be number"
    );
    assert!(
        session["message"].is_string(),
        "session.message must be string"
    );
}

// ---------------------------------------------------------------------------
// POST /auth — LoginUseCase wired → real authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_correct_password_succeeds_when_login_use_case_wired() {
    let pool = helpers::create_test_db().await;
    let login_uc = build_login_use_case();
    let app = helpers::create_pihole_test_app_with_auth(pool, login_uc, "admin").await;

    let body = serde_json::json!({ "password": "correct-password" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert_eq!(json["session"]["valid"], true);
    let sid = json["session"]["sid"].as_str().expect("sid must be string");
    assert!(!sid.is_empty(), "sid must be non-empty on successful login");
    assert_eq!(json["session"]["validity"], 1800);
}

#[tokio::test]
async fn login_with_wrong_password_returns_unauthorized() {
    let pool = helpers::create_test_db().await;
    let login_uc = build_login_use_case();
    let app = helpers::create_pihole_test_app_with_auth(pool, login_uc, "admin").await;

    let body = serde_json::json!({ "password": "wrong-password" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert_eq!(json["session"]["valid"], false);
    assert_eq!(
        json["session"]["message"].as_str().unwrap(),
        "Incorrect password"
    );
}

// ---------------------------------------------------------------------------
// Session ID format
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_id_is_32_char_hex_when_no_login_use_case() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "password": "any" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let sid = json["session"]["sid"].as_str().expect("sid must be string");
    assert_eq!(
        sid.len(),
        32,
        "session id should be 32 hex chars (16 bytes)"
    );
    assert!(
        sid.chars().all(|c| c.is_ascii_hexdigit()),
        "session id must be valid hex"
    );
}
