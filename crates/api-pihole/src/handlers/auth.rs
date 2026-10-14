use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Extension, Json,
};

use ferrous_dns_application::use_cases::LoginOutcome;
use ferrous_dns_domain::{AuthSession, DomainError};
use tracing::warn;

use crate::{
    crud::unix_seconds,
    dto::auth::{
        AuthResponse, LoginRequest, SessionEntry, SessionInfo, SessionTls, SessionsResponse,
    },
    errors::{pihole_error_response, PiholeApiError},
    extract::PiholeJson,
    middleware::extract_sid,
    state::PiholeAppState,
};

/// FTL's `message` for a valid session presented to `/auth`.
const SESSION_VALID: &str = "correct password";

/// Pi-hole v6 GET /api/auth — returns the state of the presented session.
///
/// As in FTL, a missing or unknown session is a 401 carrying the session
/// object; with `[auth]` disabled the reply is FTL's no-password session.
#[utoipa::path(
    get,
    path = "/auth",
    tag = "pihole:auth",
    responses(
        (status = 200, description = "Valid session, or no password set", body = AuthResponse),
        (status = 401, description = "No session or an unknown one", body = AuthResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_session(
    State(state): State<PiholeAppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = auth_admin(&state).await else {
        return session_response(StatusCode::OK, no_password_session());
    };
    let totp = match admin_has_totp(&state, &admin).await {
        Ok(totp) => totp,
        Err(err) => return PiholeApiError(err).into_response(),
    };

    match presented_session(&state, &headers, &uri).await {
        Ok(session) => session_response(
            StatusCode::OK,
            valid_session(
                &session,
                totp,
                seconds_left(&session.expires_at),
                SESSION_VALID,
            ),
        ),
        Err(message) => session_response(
            StatusCode::UNAUTHORIZED,
            unauthenticated_session(totp, message),
        ),
    }
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
///
/// As in FTL, a body without `password` is a 400 whatever the session, and an
/// empty `password` with a valid session returns that session.
#[utoipa::path(
    post,
    path = "/auth",
    tag = "pihole:auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "No `password`, or second factor required but no `totp` sent"),
        (status = 401, description = "Incorrect password or 2FA code", body = AuthResponse),
        (status = 429, description = "Too many failed attempts from this client")
    ),
    security()
)]
pub async fn login(
    State(state): State<PiholeAppState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    uri: Uri,
    PiholeJson(body): PiholeJson<LoginRequest>,
) -> Response {
    let Some(password) = body.password else {
        return pihole_error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "No password found in JSON payload",
            None,
        );
    };
    let Some(admin) = auth_admin(&state).await else {
        return session_response(StatusCode::OK, no_password_session());
    };
    let totp = match admin_has_totp(&state, &admin).await {
        Ok(totp) => totp,
        Err(err) => return PiholeApiError(err).into_response(),
    };

    if password.is_empty() {
        if let Ok(session) = presented_session(&state, &headers, &uri).await {
            return session_response(
                StatusCode::OK,
                valid_session(
                    &session,
                    totp,
                    seconds_left(&session.expires_at),
                    SESSION_VALID,
                ),
            );
        }
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
        .execute(&admin, &password, peer_ip, &ip_address, user_agent)
        .await;
    match app_login {
        Ok(session) => return logged_in(&state, &session, totp, "app-password correct"),
        Err(DomainError::InvalidCredentials) => {}
        Err(err) => return PiholeApiError(err).into_response(),
    }

    let outcome = state
        .auth
        .login
        .execute(&admin, &password, false, peer_ip, &ip_address, user_agent)
        .await;

    match outcome {
        Ok(LoginOutcome::Authenticated(session)) => {
            logged_in(&state, &session, totp, "password correct")
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
                Ok(session) => logged_in(&state, &session, totp, "password correct"),
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
                unauthenticated_session(totp, "password incorrect"),
            )
        }
        Err(err) => PiholeApiError(err).into_response(),
    }
}

fn logged_in(state: &PiholeAppState, session: &AuthSession, totp: bool, message: &str) -> Response {
    session_response(
        StatusCode::OK,
        valid_session(
            session,
            totp,
            state.auth.login.session_max_age(false),
            message,
        ),
    )
}

/// Pi-hole v6 DELETE /api/auth — ends the presented session.
///
/// As in FTL, there is no session to end without a password set, so that is
/// a 401 with the no-password session object.
#[utoipa::path(
    delete,
    path = "/auth",
    tag = "pihole:auth",
    responses(
        (status = 204, description = "Session terminated"),
        (status = 401, description = "No valid session presented, or no password set", body = AuthResponse)
    ),
    security(("session_id" = []))
)]
pub async fn logout(State(state): State<PiholeAppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = auth_admin(&state).await else {
        return session_response(StatusCode::UNAUTHORIZED, no_password_session());
    };

    let session = match presented_session(&state, &headers, &uri).await {
        Ok(session) => session,
        Err(message) => {
            return match admin_has_totp(&state, &admin).await {
                Ok(totp) => session_response(
                    StatusCode::UNAUTHORIZED,
                    unauthenticated_session(totp, message),
                ),
                Err(err) => PiholeApiError(err).into_response(),
            };
        }
    };

    match state.auth.logout.execute(&session.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => PiholeApiError(err).into_response(),
    }
}

/// Pi-hole v6 GET /api/auth/sessions — the live sessions, oldest first.
///
/// FTL numbers sessions by slot. Ferrous's ids are secret tokens, so each
/// session is listed under a number derived from a hash of its id (see
/// [`session_number`]). Whether a login came through an app password or a
/// proxy is not recorded, so `app` is false and `x_forwarded_for` null.
#[utoipa::path(
    get,
    path = "/auth/sessions",
    tag = "pihole:auth",
    responses(
        (status = 200, description = "Live sessions", body = SessionsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_sessions(
    State(state): State<PiholeAppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<SessionsResponse>, PiholeApiError> {
    let current = extract_sid(&headers, &uri);
    let tls = state.system.https_port != 0;
    let mut sessions = state.auth.get_active_sessions.execute().await?;
    sessions.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    let sessions = sessions
        .iter()
        .map(|session| SessionEntry {
            id: session_number(&session.id),
            current_session: current.as_deref() == Some(session.id.as_ref()),
            valid: true,
            tls: SessionTls {
                login: tls,
                mixed: false,
            },
            login_at: unix_seconds(Some(&session.created_at)),
            last_active: unix_seconds(Some(&session.last_seen_at)),
            valid_until: unix_seconds(Some(&session.expires_at)),
            remote_addr: session.ip_address.to_string(),
            user_agent: Some(session.user_agent.to_string()).filter(|agent| !agent.is_empty()),
            x_forwarded_for: None,
            app: false,
            cli: false,
        })
        .collect();
    Ok(Json(SessionsResponse { sessions }))
}

/// Pi-hole v6 DELETE /api/auth/session/{id} — ends the session listed under
/// `id`, with FTL's 400s for an id that is not a number, is negative, or
/// names no live session.
#[utoipa::path(
    delete,
    path = "/auth/session/{id}",
    tag = "pihole:auth",
    params(("id" = i64, Path, description = "Session number from /auth/sessions")),
    responses(
        (status = 204, description = "Session ended"),
        (status = 400, description = "Invalid id, or no live session under it")
    ),
    security(("session_id" = []))
)]
pub async fn delete_session(
    State(state): State<PiholeAppState>,
    Path(id): Path<String>,
) -> Response {
    let bad_request = |message: &str| {
        pihole_error_response(StatusCode::BAD_REQUEST, "bad_request", message, None)
    };
    let Ok(number) = id.trim().parse::<i64>() else {
        return bad_request("Missing or invalid session ID");
    };
    if number < 0 {
        return bad_request("Session ID out of bounds");
    }

    let sessions = match state.auth.get_active_sessions.execute().await {
        Ok(sessions) => sessions,
        Err(err) => return PiholeApiError(err).into_response(),
    };
    let Some(session) = sessions.iter().find(|s| session_number(&s.id) == number) else {
        return bad_request("Session ID not in use");
    };
    match state.auth.logout.execute(&session.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => PiholeApiError(err).into_response(),
    }
}

/// The number a session is listed under: 31 bits of a hash of its id, so
/// nothing of the token itself is shown.
fn session_number(id: &str) -> i64 {
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    (hasher.finish() >> 33) as i64
}

/// The admin account Pi-hole logins act on, or `None` with `[auth]` disabled.
async fn auth_admin(state: &PiholeAppState) -> Option<String> {
    let config = state.system.config.read().await;
    config
        .auth
        .enabled
        .then(|| config.auth.admin.username.clone())
}

async fn admin_has_totp(state: &PiholeAppState, admin: &str) -> Result<bool, DomainError> {
    Ok(state.auth.get_mfa_status.execute(admin).await?.totp_enabled)
}

/// The live session the request presents, or FTL's `message` for why there
/// is none. An expired session is deleted on lookup, so it reads as unknown.
async fn presented_session(
    state: &PiholeAppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<AuthSession, &'static str> {
    let sid = extract_sid(headers, uri).ok_or("no SID provided")?;
    state
        .auth
        .validate_session
        .execute(&sid)
        .await
        .map_err(|_| "session unknown")
}

fn session_response(status: StatusCode, session: SessionInfo) -> Response {
    (status, Json(AuthResponse { session })).into_response()
}

fn valid_session(session: &AuthSession, totp: bool, validity: i64, message: &str) -> SessionInfo {
    SessionInfo {
        valid: true,
        totp,
        sid: Some(session.id.to_string()),
        csrf: Some(None),
        validity,
        message: message.to_string(),
    }
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

fn unauthenticated_session(totp: bool, message: &str) -> SessionInfo {
    SessionInfo {
        valid: false,
        totp,
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
