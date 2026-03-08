use axum::routing::{delete, get, post};
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use tracing::debug;

use crate::dto::auth::{
    AuthStatusResponse, ChangePasswordRequest, LoginRequest, LoginResponse, SessionResponse,
    SetupPasswordRequest,
};
use crate::errors::ApiError;
use crate::state::AppState;

pub const SESSION_COOKIE_NAME: &str = "ferrous_session";

/// Routes that require authentication (behind require_auth middleware).
pub fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/password", post(change_password))
        .route("/auth/sessions", get(get_active_sessions))
        .route("/auth/sessions/{id}", delete(delete_session))
}

/// Public: returns auth status (no auth required).
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
pub async fn setup_password_public(
    State(state): State<AppState>,
    Json(req): Json<SetupPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    state.auth.setup_password.execute(&req.password).await?;
    debug!("Admin password setup completed");
    Ok(StatusCode::NO_CONTENT)
}

/// Public: login and create session (no auth required).
pub async fn login_public(
    State(state): State<AppState>,
    request: Request,
) -> Result<impl IntoResponse, ApiError> {
    let ip_address = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);

    let body = axum::body::to_bytes(request.into_body(), 1024 * 16)
        .await
        .map_err(|_| {
            ApiError(ferrous_dns_domain::DomainError::InvalidInput(
                "Invalid request body".to_string(),
            ))
        })?;

    let req: LoginRequest = serde_json::from_slice(&body).map_err(|_| {
        ApiError(ferrous_dns_domain::DomainError::InvalidInput(
            "Invalid request body".to_string(),
        ))
    })?;

    let session = state
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

    let max_age = state.auth.login.session_max_age(req.remember_me);

    let secure_flag = if state.tls_enabled { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={}; HttpOnly; SameSite=Strict{secure_flag}; Path=/; Max-Age={max_age}",
        session.id
    );

    debug!(username = %session.username, "Login successful");

    let response = (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            username: session.username.to_string(),
            role: session.role.as_str().to_string(),
            expires_at: session.expires_at.clone(),
        }),
    );

    Ok(response)
}

/// Public: logout and clear session cookie (no auth required).
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

async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.auth.logout.execute(&id).await?;
    debug!(session_id = %id, "Session deleted");
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
