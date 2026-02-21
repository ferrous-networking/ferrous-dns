use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if is_read_only_method(request.method()) {
        return Ok(next.run(request).await);
    }
    match state.api_key.as_deref() {
        None => Ok(next.run(request).await),
        Some(expected) => verify_request(request, next, expected).await,
    }
}

pub fn is_read_only_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

async fn verify_request(
    request: Request,
    next: Next,
    expected: &str,
) -> Result<Response, StatusCode> {
    let provided = extract_api_key(&request).ok_or(StatusCode::UNAUTHORIZED)?;
    if !timing_safe_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

fn extract_api_key(request: &Request) -> Option<String> {
    request
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

pub fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
