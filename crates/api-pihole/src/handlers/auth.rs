use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use ferrous_dns_application::use_cases::LoginOutcome;

use crate::{
    dto::auth::{AuthResponse, LoginRequest, SessionInfo},
    state::PiholeAppState,
};

/// Pi-hole v6 GET /api/auth — returns current session state.
#[utoipa::path(
    get,
    path = "/auth",
    tag = "pihole:auth",
    responses(
        (status = 200, description = "Current session state", body = AuthResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_session() -> Json<AuthResponse> {
    Json(AuthResponse {
        session: unauthenticated_session("Use POST /api/auth with your password"),
    })
}

/// Pi-hole v6 POST /api/auth — validates credentials and returns a session.
///
/// Uses `LoginUseCase` to create a real Ferrous DNS session.
/// If no `LoginUseCase` is wired, allows unauthenticated access.
#[utoipa::path(
    post,
    path = "/auth",
    tag = "pihole:auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "Incorrect password", body = AuthResponse)
    ),
    security()
)]
pub async fn login(
    State(state): State<PiholeAppState>,
    Json(body): Json<LoginRequest>,
) -> Response {
    if let (Some(ref login_uc), Some(ref admin_user)) = (&state.login, &state.admin_username) {
        match login_uc
            .execute(
                admin_user,
                &body.password,
                false,
                "pihole-api",
                "pihole-client",
            )
            .await
        {
            Ok(LoginOutcome::Authenticated(session)) => {
                return (
                    StatusCode::OK,
                    Json(AuthResponse {
                        session: SessionInfo {
                            valid: true,
                            totp: false,
                            sid: session.id.to_string(),
                            csrf: String::new(),
                            validity: 1_800,
                            message: String::new(),
                        },
                    }),
                )
                    .into_response();
            }
            // Password OK but a second factor is enrolled. The Pi-hole v6
            // protocol has no challenge exchange, so signal that 2FA is
            // required (clients should use the native /auth/2fa flow).
            Ok(LoginOutcome::MfaRequired { .. }) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthResponse {
                        session: SessionInfo {
                            valid: false,
                            totp: true,
                            sid: String::new(),
                            csrf: String::new(),
                            validity: 0,
                            message: "Two-factor authentication required".to_string(),
                        },
                    }),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthResponse {
                        session: unauthenticated_session("Incorrect password"),
                    }),
                )
                    .into_response();
            }
        }
    }

    // No LoginUseCase wired — allow unauthenticated access
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
}

/// Pi-hole v6 DELETE /api/auth — session logout.
#[utoipa::path(
    delete,
    path = "/auth",
    tag = "pihole:auth",
    responses(
        (status = 204, description = "Session terminated")
    ),
    security(("session_id" = []))
)]
pub async fn logout() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn generate_session_id() -> String {
    use ring::rand::SecureRandom;
    use std::fmt::Write;

    let mut buf = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .expect("OS CSPRNG unavailable");
    let mut hex = String::with_capacity(32);
    for byte in &buf {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
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
