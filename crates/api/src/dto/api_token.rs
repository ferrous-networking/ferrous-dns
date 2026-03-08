use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateApiTokenRequest {
    pub name: String,
    /// Optional custom token value (e.g. import an existing Pi-hole API key).
    /// When omitted, a secure random token is generated automatically.
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateApiTokenRequest {
    pub name: String,
    /// Optional new token value. When provided, replaces the existing key.
    /// Useful for importing an API key from another system.
    pub token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreatedApiTokenResponse {
    pub id: i64,
    pub name: String,
    pub key_prefix: String,
    pub token: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiTokenResponse {
    pub id: i64,
    pub name: String,
    pub key_prefix: String,
    pub token: Option<String>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}
