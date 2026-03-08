use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: bool,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub username: String,
    pub role: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupPasswordRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub enabled: bool,
    pub setup_required: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub ip_address: String,
    pub user_agent: String,
    pub remember_me: bool,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
}
