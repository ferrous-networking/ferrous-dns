use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::{
    dto::auth::{AuthResponse, LoginRequest, SessionInfo},
    state::PiholeAppState,
};

/// Pi-hole v6 GET /api/auth — returns current session state.
///
/// Without server-side session tracking, this always returns unauthenticated.
/// Pi-hole clients should POST /api/auth to obtain a session.
pub async fn get_session() -> Json<AuthResponse> {
    Json(AuthResponse {
        session: unauthenticated_session("Use POST /api/auth with your API key"),
    })
}

/// Pi-hole v6 POST /api/auth — validates an API key and returns a session.
pub async fn login(
    State(state): State<PiholeAppState>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let authenticated = match &state.api_key {
        Some(key) => constant_time_eq(key.as_ref().as_bytes(), body.password.as_bytes()),
        None => true,
    };

    if authenticated {
        let sid = generate_session_id();
        (
            StatusCode::OK,
            Json(AuthResponse {
                session: SessionInfo {
                    valid: true,
                    totp: false,
                    sid,
                    csrf: String::new(),
                    validity: 1_800,
                    message: String::new(),
                },
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                session: unauthenticated_session("Incorrect password"),
            }),
        )
            .into_response()
    }
}

/// Pi-hole v6 DELETE /api/auth — session logout (no-op in Ferrous DNS).
pub async fn logout() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", nanos, std::process::id())
}

fn unauthenticated_session(message: &str) -> SessionInfo {
    SessionInfo {
        valid: false,
        totp: false,
        sid: String::new(),
        csrf: String::new(),
        validity: 0,
        message: message.to_string(),
    }
}

/// Constant-time byte comparison to prevent timing side-channels on API key.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        diff |= x ^ y;
    }
    diff == 0
}
