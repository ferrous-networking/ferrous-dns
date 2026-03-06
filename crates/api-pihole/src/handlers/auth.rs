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
/// Since Ferrous DNS uses a stateless API key model, sessions are not
/// persisted. This endpoint always reports a valid guest session so
/// Pi-hole compatible clients can discover the auth capability.
pub async fn get_session() -> Json<AuthResponse> {
    Json(AuthResponse {
        session: unauthenticated_session("Use POST /api/auth with your API key"),
    })
}

/// Pi-hole v6 POST /api/auth — validates an API key and returns a session.
///
/// Pi-hole v6 clients send `{ "password": "<key>" }`. Ferrous DNS maps this
/// to its own API key. On success the returned `sid` is the API key itself,
/// which clients include as `sid` in subsequent requests.
pub async fn login(
    State(state): State<PiholeAppState>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let authenticated = match &state.api_key {
        Some(key) => key.as_ref() == body.password.as_str(),
        // No API key configured — any password is accepted (open access)
        None => true,
    };

    if authenticated {
        let sid = body.password.clone();
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
