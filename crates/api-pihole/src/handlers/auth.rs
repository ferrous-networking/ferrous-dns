use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Extension, Json,
};

use ferrous_dns_application::use_cases::LoginOutcome;
use ferrous_dns_domain::{AuthSession, DomainError};
use tracing::warn;

use crate::{
    dto::auth::{AuthResponse, LoginRequest, SessionInfo},
    errors::{pihole_error_response, PiholeApiError},
    extract::PiholeJson,
    middleware::extract_sid,
    state::PiholeAppState,
};

/// Pi-hole v6 GET /api/auth — returns the state of the presented session.
#[utoipa::path(
    get,
    path = "/auth",
    tag = "pihole:auth",
    responses(
        (status = 200, description = "Current session state", body = AuthResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_session(
    State(state): State<PiholeAppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Json<AuthResponse> {
    if !state.auth_enabled().await {
        return Json(AuthResponse {
            session: no_password_session(),
        });
    }

    let session = match extract_sid(&headers, &uri) {
        Some(sid) => state.auth.validate_session.execute(&sid).await.ok(),
        None => None,
    };
    let session = match session {
        Some(session) => SessionInfo {
            valid: true,
            totp: false,
            sid: Some(session.id.to_string()),
            csrf: None,
            validity: seconds_left(&session.expires_at),
            message: String::new(),
        },
        None => unauthenticated_session("Use POST /api/auth with your password"),
    };
    Json(AuthResponse { session })
}

/// Pi-hole v6 POST /api/auth — validates credentials and returns a session.
///
/// Accepts what FTL accepts: the admin password, or an app password (an API
/// token here), which skips the second factor. The app password is tried
/// first — FTL tries it second — so the password check that follows is the
/// one that counts a wrong attempt toward the lockout, exactly once. When the
/// account has a second factor, the TOTP code rides in the same request.
/// With `[auth]` disabled there is nothing to check — like a Pi-hole with no
/// password set, the reply is a valid session with no `sid`.
#[utoipa::path(
    post,
    path = "/auth",
    tag = "pihole:auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "Second factor required but no `totp` sent"),
        (status = 401, description = "Incorrect password or 2FA code", body = AuthResponse),
        (status = 429, description = "Too many failed attempts from this client")
    ),
    security()
)]
pub async fn login(
    State(state): State<PiholeAppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    PiholeJson(body): PiholeJson<LoginRequest>,
) -> Response {
    let (auth_enabled, admin) = {
        let config = state.system.config.read().await;
        (config.auth.enabled, config.auth.admin.username.clone())
    };
    if !auth_enabled {
        return session_response(StatusCode::OK, no_password_session());
    }

    let peer_ip = connect_info.map_or(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        |Extension(ConnectInfo(addr))| addr.ip(),
    );
    let ip_address = peer_ip.to_string();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("pihole-client");

    let app_login = state
        .auth
        .app_password_login
        .execute(&admin, &body.password, peer_ip, &ip_address, user_agent)
        .await;
    match app_login {
        Ok(session) => return logged_in(&state, &session, false, "app-password correct"),
        Err(DomainError::InvalidCredentials) => {}
        Err(err) => return PiholeApiError(err).into_response(),
    }

    let outcome = state
        .auth
        .login
        .execute(
            &admin,
            &body.password,
            false,
            peer_ip,
            &ip_address,
            user_agent,
        )
        .await;

    match outcome {
        Ok(LoginOutcome::Authenticated(session)) => {
            logged_in(&state, &session, false, "password correct")
        }
        Ok(LoginOutcome::MfaRequired {
            challenge_token, ..
        }) => {
            let Some(code) = body.totp else {
                return pihole_error_response(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "No 2FA token found in JSON payload",
                    None,
                );
            };
            let verified = state
                .auth
                .verify_mfa
                .execute(
                    &challenge_token,
                    &code.to_code(),
                    peer_ip,
                    &ip_address,
                    user_agent,
                )
                .await;
            match verified {
                Ok(session) => logged_in(&state, &session, true, "password correct"),
                Err(DomainError::InvalidMfaCode) => pihole_error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Invalid 2FA token",
                    None,
                ),
                Err(err) => PiholeApiError(err).into_response(),
            }
        }
        Err(DomainError::InvalidCredentials) => {
            // Until v0.9.19 this endpoint accepted any password, so an
            // integration can hold a key that was never valid here.
            warn!(
                client = %peer_ip,
                user_agent,
                "Pi-hole API login rejected: the password is neither the admin password nor an \
                 API token. If this is an integration using an API key or Pi-hole app password, \
                 add that key under Settings > API > API Tokens > Custom Token"
            );
            session_response(
                StatusCode::UNAUTHORIZED,
                unauthenticated_session("password incorrect"),
            )
        }
        Err(err) => PiholeApiError(err).into_response(),
    }
}

fn logged_in(state: &PiholeAppState, session: &AuthSession, totp: bool, message: &str) -> Response {
    session_response(
        StatusCode::OK,
        SessionInfo {
            valid: true,
            totp,
            sid: Some(session.id.to_string()),
            csrf: None,
            validity: state.auth.login.session_max_age(false),
            message: message.to_string(),
        },
    )
}

/// Pi-hole v6 DELETE /api/auth — ends the presented session.
#[utoipa::path(
    delete,
    path = "/auth",
    tag = "pihole:auth",
    responses(
        (status = 204, description = "Session terminated"),
        (status = 401, description = "No valid session presented", body = AuthResponse)
    ),
    security(("session_id" = []))
)]
pub async fn logout(State(state): State<PiholeAppState>, headers: HeaderMap, uri: Uri) -> Response {
    if !state.auth_enabled().await {
        return StatusCode::NO_CONTENT.into_response();
    }

    let session = match extract_sid(&headers, &uri) {
        Some(sid) => state.auth.validate_session.execute(&sid).await.ok(),
        None => None,
    };
    let Some(session) = session else {
        return session_response(
            StatusCode::UNAUTHORIZED,
            unauthenticated_session("No valid session"),
        );
    };

    match state.auth.logout.execute(&session.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => PiholeApiError(err).into_response(),
    }
}

fn session_response(status: StatusCode, session: SessionInfo) -> Response {
    (status, Json(AuthResponse { session })).into_response()
}

/// FTL's reply when no password is set: every request is already authorised.
fn no_password_session() -> SessionInfo {
    SessionInfo {
        valid: true,
        totp: false,
        sid: None,
        csrf: None,
        validity: -1,
        message: "no password set".to_string(),
    }
}

fn unauthenticated_session(message: &str) -> SessionInfo {
    SessionInfo {
        valid: false,
        totp: false,
        sid: None,
        csrf: None,
        validity: -1,
        message: message.to_string(),
    }
}

/// Seconds until `expires_at` (`%Y-%m-%d %H:%M:%S`, UTC); 0 once it has passed.
fn seconds_left(expires_at: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|expiry| {
            (expiry - chrono::Utc::now().naive_utc())
                .num_seconds()
                .max(0)
        })
        .unwrap_or(0)
}
