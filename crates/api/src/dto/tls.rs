use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct TlsStatusResponse {
    pub enabled: bool,
    pub cert_exists: bool,
    pub key_exists: bool,
    pub cert_subject: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_valid: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct TlsUploadResponse {
    pub success: bool,
    pub message: String,
    pub restart_required: bool,
}

#[derive(Deserialize, Debug)]
pub struct GenerateQuery {
    #[serde(default)]
    pub force: bool,
}
