use serde::Serialize;

/// Pi-hole v6 GET /api/search/:domain response.
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
}

/// A single search result showing which list matched.
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub domain: String,
    pub r#type: &'static str,
    pub kind: &'static str,
    pub source: String,
    pub blocked: bool,
}
