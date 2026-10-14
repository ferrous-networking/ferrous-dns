use serde::Serialize;
use utoipa::ToSchema;

use crate::dto::domains::PiholeDomainEntry;
use crate::dto::lists::PiholeListEntry;

/// Pi-hole v6 GET /api/search/{domain} response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub search: SearchData,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchData {
    /// Domain-list entries: exact entries named by the search, then regex
    /// filters that match it.
    pub domains: Vec<SearchDomainEntry>,
    /// The lists that hold the domain.
    pub gravity: Vec<SearchGravityEntry>,
    pub results: SearchResults,
    pub parameters: SearchParameters,
}

/// A domain-list entry as search.c lists it: no `unicode`.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchDomainEntry {
    pub domain: String,
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

impl From<PiholeDomainEntry> for SearchDomainEntry {
    fn from(e: PiholeDomainEntry) -> Self {
        Self {
            domain: e.domain,
            r#type: e.r#type,
            kind: e.kind,
            comment: e.comment,
            groups: e.groups,
            enabled: e.enabled,
            id: e.id,
            date_added: e.date_added,
            date_modified: e.date_modified,
        }
    }
}

/// A list that holds the searched domain.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchGravityEntry {
    /// The searched domain. FTL names the list line that matched, which may
    /// be an ABP pattern; Ferrous's compiled index does not keep it.
    pub domain: String,
    #[serde(flatten)]
    pub list: PiholeListEntry,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResults {
    pub domains: SearchResultsDomains,
    pub gravity: SearchResultsGravity,
    pub total: u64,
}

/// Matches before `N` caps the rows.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResultsDomains {
    pub exact: u64,
    pub regex: u64,
}

/// Matches before `N` caps the rows.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResultsGravity {
    pub allow: u64,
    pub block: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchParameters {
    #[serde(rename = "N")]
    pub n: u32,
    pub partial: bool,
    /// The domain as requested.
    pub domain: String,
    pub debug: bool,
}
