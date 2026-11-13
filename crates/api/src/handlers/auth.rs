use axum::{
    extract::{ConnectInfo, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use ferrous_dns_application::use_cases::{IssuedSession, LoginOutcome};
use ferrous_dns_domain::{forwarded_client_ip, AuthSession, DomainError, MfaMethod};

use crate::dto::auth::{
    AuthStatusResponse, ChangePasswordRequest, ConfirmTotpRequest, DisableMfaRequest,
    DiscoverableFinishRequest, DiscoverableStartResponse, LoginRequest, LoginResponse,
    MfaStatusResponse, PasskeyResponse, RecoveryCodesResponse, RegisterPasskeyFinishRequest,
    SessionResponse, SetupPasswordRequest, SetupTotpResponse, VerifyMfaRequest,
    WebauthnAuthFinishRequest, WebauthnAuthStartRequest, WebauthnRegisterStartResponse,
};
use crate::errors::ApiError;
use crate::state::AppState;

pub const SESSION_COOKIE_NAME: &str = "ferrous_session";

/// Routes that require authentication (behind require_auth middleware).
pub fn protected_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(change_password))
        .routes(routes!(get_active_sessions))
        .routes(routes!(delete_session))
        .routes(routes!(get_mfa_status))
        .routes(routes!(setup_totp))
        .routes(routes!(confirm_totp))
        .routes(routes!(disable_mfa))
        .routes(routes!(register_passkey_start))
        .routes(routes!(register_passkey_finish))
        .routes(routes!(delete_passkey))
}

/// Public MFA routes (challenge-gated, no session yet).
pub fn public_mfa_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(verify_mfa_public))
        .routes(routes!(webauthn_authenticate_start_public))
        .routes(routes!(webauthn_authenticate_finish_public))
        .routes(routes!(webauthn_discoverable_start_public))
        .routes(routes!(webauthn_discoverable_finish_public))
}

/// Builds the `Set-Cookie` header value for a session; an empty id with
/// `max_age` 0 clears it.
fn session_cookie(token: &str, max_age: i64, tls_enabled: bool) -> String {
    let secure_flag = if tls_enabled { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict{secure_flag}; Path=/; Max-Age={max_age}"
    )
}

/// 200 response that sets the session cookie for a completed login.
fn session_established(state: &AppState, issued: IssuedSession) -> Response {
    let IssuedSession { session, token } = issued;
    let max_age = state.auth.login.session_max_age(session.remember_me);
    let cookie = session_cookie(&token, max_age, state.tls_enabled);
    (
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            mfa_required: false,
            username: Some(session.username.to_string()),
            role: Some(session.role.as_str()),
            expires_at: Some(session.expires_at),
            ..Default::default()
        }),
    )
        .into_response()
}

/// Session named by the request's session cookie, or 401.
async fn current_session(state: &AppState, headers: &HeaderMap) -> Result<AuthSession, ApiError> {
    let token = extract_session_cookie(headers).ok_or(ApiError(DomainError::AuthRequired))?;
    Ok(state.auth.validate_session.execute(token).await?)
}

/// Username of the session named by the request's session cookie, or 401.
async fn session_username(state: &AppState, headers: &HeaderMap) -> Result<Arc<str>, ApiError> {
    Ok(current_session(state, headers).await?.username)
}

/// Reads and JSON-decodes a request body (16 KiB cap), mapping failures to 400.
async fn read_json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    fn invalid<E>(_: E) -> ApiError {
        ApiError(DomainError::InvalidInput(
            "Invalid request body".to_string(),
        ))
    }
    let body = axum::body::to_bytes(request.into_body(), 1024 * 16)
        .await
        .map_err(invalid)?;
    serde_json::from_slice(&body).map_err(invalid)
}

/// Public: returns auth status (no auth required).
#[utoipa::path(
    get,
    path = "/auth/status",
    tag = "auth",
    responses(
        (status = 200, description = "Authentication status", body = AuthStatusResponse),
    ),
    security(),
)]
pub async fn get_auth_status_public(
    State(state): State<AppState>,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let status = state.auth.get_auth_status.execute().await;
    debug!(
        enabled = status.auth_enabled,
        setup_required = !status.password_configured,
        "Auth status checked"
    );
    Ok(Json(AuthStatusResponse {
        enabled: status.auth_enabled,
        setup_required: !status.password_configured,
    }))
}

/// Public: first-run password setup (no auth required).
#[utoipa::path(
    post,
    path = "/auth/setup",
    tag = "auth",
    request_body = SetupPasswordRequest,
    responses(
        (status = 204, description = "Password configured"),
        (status = 409, description = "Password already configured"),
        (status = 400, description = "Invalid password"),
    ),
    security(),
)]
pub async fn setup_password_public(
    State(state): State<AppState>,
    Json(req): Json<SetupPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    state.auth.setup_password.execute(&req.password).await?;
    debug!("Admin password setup completed");
    Ok(StatusCode::NO_CONTENT)
}

/// Public: login and create session (no auth required).
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful, session cookie issued", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Too many login attempts"),
    ),
    security(),
)]
pub async fn login_public(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let peer_ip = extract_peer_ip(&request);
    let ip_address = session_client_ip(&state, peer_ip, request.headers()).await;
    let user_agent = extract_user_agent(&request);

    let req: LoginRequest = read_json(request).await?;

    let outcome = state
        .auth
        .login
        .execute(
            &req.username,
            &req.password,
            req.remember_me,
            peer_ip,
            &ip_address,
            &user_agent,
        )
        .await?;

    match outcome {
        LoginOutcome::Authenticated(issued) => {
            debug!(username = %issued.session.username, "Login successful");
            Ok(session_established(&state, issued))
        }
        LoginOutcome::MfaRequired {
            challenge_token,
            methods,
        } => {
            debug!(username = %req.username, "Login requires second factor");
            Ok(Json(LoginResponse {
                mfa_required: true,
                challenge_token: Some(challenge_token),
                methods: methods.iter().map(MfaMethod::as_str).collect(),
                ..Default::default()
            })
            .into_response())
        }
    }
}

/// Public: complete a second-factor login with a TOTP or recovery code.
#[utoipa::path(
    post,
    path = "/auth/2fa/verify",
    tag = "auth",
    request_body = VerifyMfaRequest,
    responses(
        (status = 200, description = "MFA verified, session cookie issued", body = LoginResponse),
        (status = 401, description = "Invalid or expired code/challenge"),
    ),
    security(),
)]
pub async fn verify_mfa_public(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let peer_ip = extract_peer_ip(&request);
    let ip_address = session_client_ip(&state, peer_ip, request.headers()).await;
    let user_agent = extract_user_agent(&request);
    let req: VerifyMfaRequest = read_json(request).await?;

    let issued = state
        .auth
        .verify_mfa
        .execute(
            &req.challenge_token,
            &req.code,
            peer_ip,
            &ip_address,
            &user_agent,
        )
        .await?;

    debug!(username = %issued.session.username, "Second factor verified");
    Ok(session_established(&state, issued))
}

/// Public: begin a passkey login for a pending MFA challenge.
#[utoipa::path(
    post,
    path = "/auth/webauthn/authenticate/start",
    tag = "auth",
    request_body = WebauthnAuthStartRequest,
    responses(
        (status = 200, description = "Assertion challenge for navigator.credentials.get"),
        (status = 400, description = "WebAuthn not configured"),
        (status = 401, description = "Challenge expired"),
    ),
    security(),
)]
pub async fn webauthn_authenticate_start_public(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: WebauthnAuthStartRequest = read_json(request).await?;
    let challenge = state
        .auth
        .authenticate_passkey
        .start(&req.challenge_token)
        .await?;
    Ok(Json(challenge))
}

/// Public: complete a passkey login.
#[utoipa::path(
    post,
    path = "/auth/webauthn/authenticate/finish",
    tag = "auth",
    request_body = WebauthnAuthFinishRequest,
    responses(
        (status = 200, description = "Passkey verified, session cookie issued", body = LoginResponse),
        (status = 401, description = "Verification failed"),
    ),
    security(),
)]
pub async fn webauthn_authenticate_finish_public(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let ip_address = session_client_ip(&state, extract_peer_ip(&request), request.headers()).await;
    let user_agent = extract_user_agent(&request);
    let req: WebauthnAuthFinishRequest = read_json(request).await?;

    let issued = state
        .auth
        .authenticate_passkey
        .finish(&req.challenge_token, req.response, &ip_address, &user_agent)
        .await?;

    debug!(username = %issued.session.username, "Passkey login verified");
    Ok(session_established(&state, issued))
}

/// Public: begin a usernameless (passwordless) passkey login.
#[utoipa::path(
    post,
    path = "/auth/webauthn/discoverable/start",
    tag = "auth",
    responses(
        (status = 200, description = "Discoverable assertion challenge + ceremony token", body = DiscoverableStartResponse),
        (status = 400, description = "WebAuthn not configured"),
        (status = 429, description = "Too many passwordless logins pending"),
    ),
    security(),
)]
pub async fn webauthn_discoverable_start_public(
    State(state): State<AppState>,
) -> Result<Json<DiscoverableStartResponse>, ApiError> {
    let start = state.auth.discoverable_passkey_login.start().await?;
    Ok(Json(DiscoverableStartResponse {
        challenge_token: start.challenge_token,
        challenge: start.challenge,
    }))
}

/// Public: complete a usernameless (passwordless) passkey login.
#[utoipa::path(
    post,
    path = "/auth/webauthn/discoverable/finish",
    tag = "auth",
    request_body = DiscoverableFinishRequest,
    responses(
        (status = 200, description = "Passkey verified, session cookie issued", body = LoginResponse),
        (status = 401, description = "Verification failed"),
    ),
    security(),
)]
pub async fn webauthn_discoverable_finish_public(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let ip_address = session_client_ip(&state, extract_peer_ip(&request), request.headers()).await;
    let user_agent = extract_user_agent(&request);
    let req: DiscoverableFinishRequest = read_json(request).await?;

    let issued = state
        .auth
        .discoverable_passkey_login
        .finish(
            &req.challenge_token,
            req.response,
            req.remember_me,
            &ip_address,
            &user_agent,
        )
        .await?;

    debug!(username = %issued.session.username, "Passwordless passkey login verified");
    Ok(session_established(&state, issued))
}

/// Public: logout and clear session cookie (no auth required).
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    responses(
        (status = 204, description = "Session cleared"),
    ),
    security(),
)]
pub async fn logout_public(State(state): State<AppState>, request: Request) -> impl IntoResponse {
    if let Some(token) = extract_session_cookie(request.headers()) {
        let _ = state.auth.logout.execute(token).await;
    }

    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session_cookie("", 0, state.tls_enabled))],
    )
}

#[utoipa::path(
    post,
    path = "/auth/password",
    tag = "auth",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 401, description = "Authentication required or current password invalid"),
        (status = 400, description = "Invalid new password"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn change_password(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    let session = current_session(&state, request.headers()).await?;
    let req: ChangePasswordRequest = read_json(request).await?;

    state
        .auth
        .change_password
        .execute(
            &session.username,
            &session.id,
            &req.current_password,
            &req.new_password,
        )
        .await?;

    debug!(username = %session.username, "Password changed via API");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/auth/sessions",
    tag = "auth",
    responses(
        (status = 200, description = "Active sessions", body = [SessionResponse]),
        (status = 401, description = "Authentication required"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_active_sessions(
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = state.auth.get_active_sessions.execute().await?;
    debug!(count = sessions.len(), "Active sessions retrieved");
    Ok(Json(
        sessions
            .into_iter()
            .map(|s| SessionResponse {
                id: s.id.to_string(),
                username: s.username.to_string(),
                role: s.role.as_str(),
                ip_address: s.ip_address.to_string(),
                user_agent: s.user_agent.to_string(),
                remember_me: s.remember_me,
                created_at: s.created_at,
                last_seen_at: s.last_seen_at,
                expires_at: s.expires_at,
            })
            .collect(),
    ))
}

#[utoipa::path(
    delete,
    path = "/auth/sessions/{id}",
    tag = "auth",
    params(("id" = String, Path, description = "Session id from `GET /auth/sessions`")),
    responses(
        (status = 204, description = "Session deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Session not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.auth.revoke_session.execute(&id).await?;
    debug!("Session deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// Protected: current second-factor enrollment status for the session user.
#[utoipa::path(
    get,
    path = "/auth/2fa/status",
    tag = "auth",
    responses(
        (status = 200, description = "MFA status", body = MfaStatusResponse),
        (status = 401, description = "Authentication required"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_mfa_status(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<MfaStatusResponse>, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    let status = state.auth.get_mfa_status.execute(&username).await?;
    Ok(Json(MfaStatusResponse {
        totp_enabled: status.totp_enabled,
        recovery_codes_remaining: status.recovery_codes_remaining,
        webauthn_configured: state.webauthn_configured,
        passkeys: status
            .passkeys
            .into_iter()
            .map(|p| PasskeyResponse {
                id: p.id,
                label: p.label,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            })
            .collect(),
    }))
}

/// Protected: begin TOTP enrollment (returns secret + QR).
#[utoipa::path(
    post,
    path = "/auth/2fa/setup",
    tag = "auth",
    responses(
        (status = 200, description = "TOTP enrollment material", body = SetupTotpResponse),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "TOTP already enabled"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn setup_totp(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<SetupTotpResponse>, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    let setup = state.auth.setup_totp.execute(&username).await?;
    debug!(username = %username, "TOTP setup issued");
    Ok(Json(SetupTotpResponse {
        secret: setup.secret,
        otpauth_uri: setup.otpauth_uri,
        qr_svg: setup.qr_svg,
    }))
}

/// Protected: confirm TOTP enrollment and receive recovery codes.
#[utoipa::path(
    post,
    path = "/auth/2fa/confirm",
    tag = "auth",
    request_body = ConfirmTotpRequest,
    responses(
        (status = 200, description = "TOTP enabled; recovery codes returned once", body = RecoveryCodesResponse),
        (status = 401, description = "Authentication required or invalid code"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn confirm_totp(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<RecoveryCodesResponse>, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    let req: ConfirmTotpRequest = read_json(request).await?;
    let codes = state
        .auth
        .confirm_totp
        .execute(&username, &req.code)
        .await?;
    debug!(username = %username, "TOTP confirmed");
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes,
    }))
}

/// Protected: disable all second factors after re-verifying the password.
#[utoipa::path(
    delete,
    path = "/auth/2fa",
    tag = "auth",
    request_body = DisableMfaRequest,
    responses(
        (status = 204, description = "Second factors disabled"),
        (status = 401, description = "Authentication required or wrong password"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn disable_mfa(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    let req: DisableMfaRequest = read_json(request).await?;
    state
        .auth
        .disable_mfa
        .execute(&username, &req.password)
        .await?;
    debug!(username = %username, "MFA disabled");
    Ok(StatusCode::NO_CONTENT)
}

/// Protected: begin passkey registration.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/start",
    tag = "auth",
    responses(
        (status = 200, description = "Creation challenge + ceremony token", body = WebauthnRegisterStartResponse),
        (status = 400, description = "WebAuthn not configured"),
        (status = 401, description = "Authentication required"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn register_passkey_start(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<WebauthnRegisterStartResponse>, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    let start = state
        .auth
        .register_passkey
        .start(&username, &username)
        .await?;
    Ok(Json(WebauthnRegisterStartResponse {
        ceremony_token: start.ceremony_token,
        challenge: start.challenge,
    }))
}

/// Protected: complete passkey registration.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/finish",
    tag = "auth",
    request_body = RegisterPasskeyFinishRequest,
    responses(
        (status = 204, description = "Passkey registered"),
        (status = 401, description = "Authentication required or ceremony expired"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn register_passkey_finish(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    let req: RegisterPasskeyFinishRequest = read_json(request).await?;
    state
        .auth
        .register_passkey
        .finish(&username, &req.ceremony_token, req.response, req.label)
        .await?;
    debug!(username = %username, "Passkey registered");
    Ok(StatusCode::NO_CONTENT)
}

/// Protected: remove a registered passkey.
#[utoipa::path(
    delete,
    path = "/auth/webauthn/{id}",
    tag = "auth",
    params(("id" = i64, Path, description = "Passkey ID")),
    responses(
        (status = 204, description = "Passkey removed"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Passkey not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_passkey(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    let username = session_username(&state, request.headers()).await?;
    state.auth.delete_passkey.execute(&username, id).await?;
    debug!(username = %username, passkey_id = id, "Passkey removed");
    Ok(StatusCode::NO_CONTENT)
}

/// Session token from the `Cookie` headers; HTTP/2 clients may send one header
/// per cookie, so every header is searched.
pub(crate) fn extract_session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
        .find_map(|cookie| {
            cookie
                .trim()
                .strip_prefix(SESSION_COOKIE_NAME)?
                .strip_prefix('=')
        })
}

/// The address a new session records: the TCP peer, unless the peer is one of
/// `[server] trusted_proxies` and names the client in a forwarding header.
async fn session_client_ip(state: &AppState, peer: IpAddr, headers: &HeaderMap) -> String {
    let config = state.config.read().await;
    forwarded_client_ip(
        peer,
        headers
            .get_all("x-forwarded-for")
            .iter()
            .map(|value| value.to_str().unwrap_or_default()),
        headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok()),
        &config.server.trusted_proxies,
    )
    .to_string()
}

/// TCP peer of the connection — the one client address a caller cannot forge,
/// so the login lockout is keyed by it. Absent only when the router is driven
/// without a listener, as in tests.
fn extract_peer_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ConnectInfo(addr)| {
            addr.ip()
        })
}

fn extract_user_agent(request: &Request) -> String {
    request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{extract_session_cookie, session_cookie};
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn session_cookie_is_found_in_any_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("theme=dark"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("ferrous_session_old=x; ferrous_session=abc"),
        );

        assert_eq!(extract_session_cookie(&headers), Some("abc"));
    }

    #[test]
    fn test_session_cookie_omits_secure_over_plain_http() {
        let cookie = session_cookie("session-id", 86400, false);

        assert!(!cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=86400"));
    }

    #[test]
    fn test_session_cookie_sets_secure_over_https() {
        let cookie = session_cookie("session-id", 86400, true);

        assert!(cookie.contains("; Secure"));
    }
}
