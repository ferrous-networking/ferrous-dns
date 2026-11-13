use crate::handlers::auth::extract_session_cookie;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

pub const API_KEY_HEADER: &str = "X-Api-Key";

/// Admits the request when auth is disabled, or when it carries a valid
/// session cookie or API token; otherwise 401.
pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !state.auth_enabled().await {
        return Ok(next.run(request).await);
    }

    if let Some(token) = extract_session_cookie(request.headers()) {
        if state.auth.validate_session.execute(token).await.is_ok() {
            return Ok(next.run(request).await);
        }
    }

    let token = request
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok());
    if let Some(token) = token {
        if state.auth.validate_api_token.execute(token).await.is_ok() {
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
