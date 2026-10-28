use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct HealthResponse {
    /// `ok` while the DNS listener is up, `unavailable` otherwise.
    #[schema(example = "ok")]
    pub status: &'static str,
    /// The server's version.
    #[schema(example = "0.10.0")]
    pub version: &'static str,
}
