use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use ferrous_dns_application::use_cases::LoginOutcome;

use crate::dto::auth::{
    AuthStatusResponse, ChangePasswordRequest, ConfirmTotpRequest, DisableMfaRequest,
    DiscoverableFinishRequest, DiscoverableStartResponse, LoginRequest, LoginResponse,
    MfaStatusResponse, PasskeyResponse, RecoveryCodesResponse, RegisterPasskeyFinishRequest,
    RegisterPasskeyStartRequest, SessionResponse, SetupPasswordRequest, SetupTotpResponse,
    VerifyMfaRequest, WebauthnAuthFinishRequest, WebauthnAuthStartRequest,
    WebauthnRegisterStartResponse,
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

/// Builds the `Set-Cookie` header value for a freshly issued session.
fn session_cookie(session_id: &str, max_age: i64, tls_enabled: bool) -> String {
    let secure_flag = if tls_enabled { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}={session_id}; HttpOnly; SameSite=Strict{secure_flag}; Path=/; Max-Age={max_age}"
    )
}

/// Resolves the authenticated username from a session id, or 401.
///
/// Takes the id by value (not `&Request`) so no non-`Send` borrow is held
/// across the `await`.
async fn require_username(state: &AppState, session_id: &str) -> Result<String, ApiError> {
    let session = state.auth.validate_session.execute(session_id).await?;
    Ok(session.username.to_string())
}

/// Extracts the session id from the request cookie, or 401.
fn require_session_id(request: &Request) -> Result<String, ApiError> {
    extract_session_cookie(request).ok_or(ApiError(ferrous_dns_domain::DomainError::AuthRequired))
}

/// Reads and JSON-decodes a request body (16 KiB cap), mapping failures to 400.
async fn read_json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    let body = axum::body::to_bytes(request.into_body(), 1024 * 16)
        .await
        .map_err(|_| {
            ApiError(ferrous_dns_domain::DomainError::InvalidInput(
                "Invalid request body".to_string(),
            ))
        })?;
    serde_json::from_slice(&body).map_err(|_| {
        ApiError(ferrous_dns_domain::DomainError::InvalidInput(
            "Invalid request body".to_string(),
        ))
    })
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
) -> Result<impl IntoResponse, ApiError> {
    let ip_address = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);

    let req: LoginRequest = read_json(request).await?;

    let outcome = state
        .auth
        .login
        .execute(
            &req.username,
            &req.password,
            req.remember_me,
            &ip_address,
            &user_agent,
        )
        .await?;

    match outcome {
        LoginOutcome::Authenticated(session) => {
            let max_age = state.auth.login.session_max_age(req.remember_me);
            let cookie = session_cookie(&session.id, max_age, state.tls_enabled);
            debug!(username = %session.username, "Login successful");
            Ok((
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(LoginResponse {
                    mfa_required: false,
                    username: Some(session.username.to_string()),
                    role: Some(session.role.as_str().to_string()),
                    expires_at: Some(session.expires_at.clone()),
                    ..Default::default()
                }),
            )
                .into_response())
        }
        LoginOutcome::MfaRequired {
            challenge_token,
            methods,
        } => {
            debug!(username = %req.username, "Login requires second factor");
            Ok(Json(LoginResponse {
                mfa_required: true,
                challenge_token: Some(challenge_token),
                methods: methods.into_iter().map(String::from).collect(),
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
) -> Result<impl IntoResponse, ApiError> {
    let ip_address = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);
    let req: VerifyMfaRequest = read_json(request).await?;

    let session = state
        .auth
        .verify_mfa
        .execute(&req.challenge_token, &req.code, &ip_address, &user_agent)
        .await?;

    let max_age = state.auth.login.session_max_age(session.remember_me);
    let cookie = session_cookie(&session.id, max_age, state.tls_enabled);
    debug!(username = %session.username, "Second factor verified");

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            mfa_required: false,
            username: Some(session.username.to_string()),
            role: Some(session.role.as_str().to_string()),
            expires_at: Some(session.expires_at.clone()),
            ..Default::default()
        }),
    ))
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
) -> Result<impl IntoResponse, ApiError> {
    let ip_address = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);
    let req: WebauthnAuthFinishRequest = read_json(request).await?;

    let session = state
        .auth
        .authenticate_passkey
        .finish(&req.challenge_token, req.response, &ip_address, &user_agent)
        .await?;

    let max_age = state.auth.login.session_max_age(session.remember_me);
    let cookie = session_cookie(&session.id, max_age, state.tls_enabled);
    debug!(username = %session.username, "Passkey login verified");

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            mfa_required: false,
            username: Some(session.username.to_string()),
            role: Some(session.role.as_str().to_string()),
            expires_at: Some(session.expires_at.clone()),
            ..Default::default()
        }),
    ))
}

/// Public: begin a usernameless (passwordless) passkey login.
#[utoipa::path(
    post,
    path = "/auth/webauthn/discoverable/start",
    tag = "auth",
    responses(
        (status = 200, description = "Discoverable assertion challenge + ceremony token", body = DiscoverableStartResponse),
        (status = 400, description = "WebAuthn not configured"),
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
) -> Result<impl IntoResponse, ApiError> {
    let ip_address = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);
    let req: DiscoverableFinishRequest = read_json(request).await?;

    let session = state
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

    let max_age = state.auth.login.session_max_age(session.remember_me);
    let cookie = session_cookie(&session.id, max_age, state.tls_enabled);
    debug!(username = %session.username, "Passwordless passkey login verified");

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            mfa_required: false,
            username: Some(session.username.to_string()),
            role: Some(session.role.as_str().to_string()),
            expires_at: Some(session.expires_at.clone()),
            ..Default::default()
        }),
    ))
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
    if let Some(session_id) = extract_session_cookie(&request) {
        let _ = state.auth.logout.execute(&session_id).await;
    }

    let secure_flag = if state.tls_enabled { "; Secure" } else { "" };
    let clear_cookie = format!(
        "{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict{secure_flag}; Path=/; Max-Age=0"
    );

    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, clear_cookie)])
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
    let session_id = extract_session_cookie(&request)
        .ok_or(ApiError(ferrous_dns_domain::DomainError::AuthRequired))?;

    let session = state
        .auth
        .validate_session
        .execute(&session_id)
        .await
        .map_err(ApiError::from)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 16)
        .await
        .map_err(|_| {
            ApiError(ferrous_dns_domain::DomainError::InvalidInput(
                "Invalid request body".to_string(),
            ))
        })?;

    let req: ChangePasswordRequest = serde_json::from_slice(&body).map_err(|_| {
        ApiError(ferrous_dns_domain::DomainError::InvalidInput(
            "Invalid request body".to_string(),
        ))
    })?;

    state
        .auth
        .change_password
        .execute(&session.username, &req.current_password, &req.new_password)
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
                role: s.role.as_str().to_string(),
                ip_address: s.ip_address.to_string(),
                user_agent: s.user_agent.to_string(),
                remember_me: s.remember_me,
                created_at: s.created_at.clone(),
                last_seen_at: s.last_seen_at.clone(),
                expires_at: s.expires_at.clone(),
            })
            .collect(),
    ))
}

#[utoipa::path(
    delete,
    path = "/auth/sessions/{id}",
    tag = "auth",
    params(("id" = String, Path, description = "Session ID")),
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
    state.auth.logout.execute(&id).await?;
    debug!(session_id = %id, "Session deleted");
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
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
    request_body = RegisterPasskeyStartRequest,
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
    let _req: RegisterPasskeyStartRequest = read_json(request).await?;
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
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
    let session_id = require_session_id(&request)?;
    let username = require_username(&state, &session_id).await?;
    state.auth.delete_passkey.execute(&username, id).await?;
    debug!(username = %username, passkey_id = id, "Passkey removed");
    Ok(StatusCode::NO_CONTENT)
}

pub fn extract_session_cookie(request: &Request) -> Option<String> {
    let cookie_header = request.headers().get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(SESSION_COOKIE_NAME) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_client_ip(request: &Request) -> String {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_user_agent(request: &Request) -> String {
    request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
