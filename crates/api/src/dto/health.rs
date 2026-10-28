use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// The DNS listener is serving.
    Ok,
    /// The DNS listener is down.
    Unavailable,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct HealthResponse {
    pub status: HealthStatus,
    /// The server's version.
    #[schema(example = "0.10.0")]
    pub version: &'static str,
}
