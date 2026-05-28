use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 POST /api/action/* response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionResponse {
    #[schema(value_type = String)]
    pub status: &'static str,
    pub message: String,
}
