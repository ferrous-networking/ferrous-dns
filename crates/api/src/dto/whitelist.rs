use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct WhitelistResponse {
    pub domain: String,
    pub added_at: String,
}
