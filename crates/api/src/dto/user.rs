use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "viewer".to_string()
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Option<i64>,
    pub username: String,
    pub display_name: Option<String>,
    pub role: String,
    pub source: String,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
