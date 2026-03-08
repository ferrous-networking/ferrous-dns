use serde::{Deserialize, Serialize};

/// Pi-hole v6 domain entry (covers both exact and regex).
#[derive(Debug, Serialize)]
pub struct PiholeDomainEntry {
    pub id: i64,
    pub domain: String,
    pub r#type: &'static str,
    pub kind: &'static str,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub groups: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
}

/// Pi-hole v6 POST/PUT domain request.
#[derive(Debug, Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    pub comment: Option<String>,
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 batch delete request.
#[derive(Debug, Deserialize)]
pub struct BatchDeleteRequest {
    pub items: Vec<String>,
}

/// Pi-hole v6 domain list response.
#[derive(Debug, Serialize)]
pub struct DomainsListResponse {
    pub domains: Vec<PiholeDomainEntry>,
}
