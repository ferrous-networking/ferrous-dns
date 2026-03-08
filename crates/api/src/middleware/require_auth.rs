use crate::handlers::auth::extract_session_cookie;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Middleware that requires authentication via session cookie or API token.
///
/// Authentication flow:
/// 1. If auth is disabled in config, allow all requests through.
/// 2. Check for session cookie (`ferrous_session`) → validate via `ValidateSessionUseCase`.
/// 3. Check for `X-Api-Key` header → validate via `ValidateApiTokenUseCase`.
/// 4. If neither is valid, return 401 Unauthorized.
pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !state.auth_enabled().await {
        return Ok(next.run(request).await);
    }

    if let Some(session_id) = extract_session_cookie(&request) {
        if state
            .auth
            .validate_session
            .execute(&session_id)
            .await
            .is_ok()
        {
            return Ok(next.run(request).await);
        }
    }

    if let Some(token) = extract_api_token(&request) {
        if state.auth.validate_api_token.execute(&token).await.is_ok() {
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn extract_api_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}
