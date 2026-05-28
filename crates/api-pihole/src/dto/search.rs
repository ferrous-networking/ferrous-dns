use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/search/:domain response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
}

/// A single search result showing which list matched.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResult {
    pub domain: String,
    #[schema(value_type = String)]
    pub r#type: &'static str,
    #[schema(value_type = String)]
    pub kind: &'static str,
    pub source: String,
    pub blocked: bool,
}
