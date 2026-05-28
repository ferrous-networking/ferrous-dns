use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct TlsStatusResponse {
    pub enabled: bool,
    pub cert_exists: bool,
    pub key_exists: bool,
    pub cert_subject: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_valid: bool,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct TlsUploadResponse {
    pub success: bool,
    pub message: String,
    pub restart_required: bool,
}

#[derive(Deserialize, Debug, IntoParams)]
pub struct GenerateQuery {
    #[serde(default)]
    pub force: bool,
}
