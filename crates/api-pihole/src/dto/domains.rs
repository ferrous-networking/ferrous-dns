use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::dto::crud::{Processed, StringOrArray};

/// Pi-hole v6 domain entry (covers both exact and regex).
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeDomainEntry {
    pub domain: String,
    /// The IDN-decoded domain. Ferrous stores domains as given, so this
    /// repeats `domain`.
    pub unicode: String,
    #[schema(value_type = String)]
    pub r#type: &'static str,
    #[schema(value_type = String)]
    pub kind: &'static str,
    pub comment: Option<String>,
    /// FTL group ids; the default group is 0.
    pub groups: Vec<i64>,
    pub enabled: bool,
    pub id: i64,
    /// Unix seconds.
    pub date_added: i64,
    /// Unix seconds.
    pub date_modified: i64,
}

/// Pi-hole v6 POST /api/domains/:type/:kind request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDomainRequest {
    pub domain: Option<StringOrArray>,
    pub comment: Option<String>,
    /// FTL group ids; Ferrous keeps the first.
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 PUT /api/domains/:type/:kind/:domain request. The entry is
/// replaced: an omitted `comment` is cleared and `enabled` defaults to true.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDomainRequest {
    /// With `kind`, the list the entry is in now; the URI names the list it
    /// moves to.
    #[serde(rename = "type")]
    pub domain_type: Option<String>,
    pub kind: Option<String>,
    pub comment: Option<String>,
    /// FTL group ids; Ferrous keeps the first.
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 domain list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DomainsListResponse {
    pub domains: Vec<PiholeDomainEntry>,
}

/// Pi-hole v6 POST/PUT domain response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DomainsWriteResponse {
    pub domains: Vec<PiholeDomainEntry>,
    pub processed: Processed,
}
