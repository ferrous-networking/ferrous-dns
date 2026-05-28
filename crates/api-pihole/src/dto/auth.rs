use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pi-hole v6 POST /api/auth request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub password: String,
}

/// Pi-hole v6 session object returned by GET/POST /api/auth.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionInfo {
    pub valid: bool,
    pub totp: bool,
    pub sid: String,
    pub csrf: String,
    pub validity: i64,
    pub message: String,
}

/// Pi-hole v6 auth response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub session: SessionInfo,
}
