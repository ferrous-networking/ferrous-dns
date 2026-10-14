use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 POST /api/action/* response: FTL's bare success body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionResponse {
    #[schema(value_type = String)]
    pub status: &'static str,
}

impl ActionResponse {
    pub fn success() -> Self {
        Self { status: "success" }
    }
}
