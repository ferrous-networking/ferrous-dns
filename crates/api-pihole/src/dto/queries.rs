use ferrous_dns_domain::BlockSource;
use serde::Serialize;

/// Pi-hole v6 GET /api/queries response.
#[derive(Debug, Serialize)]
pub struct QueriesResponse {
    pub queries: Vec<PiholeQueryEntry>,
    pub cursor: Option<i64>,
    #[serde(rename = "recordsTotal")]
    pub records_total: u64,
    #[serde(rename = "recordsFiltered")]
    pub records_filtered: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draw: Option<u32>,
}

/// Client reference returned inside a query entry.
#[derive(Debug, Serialize)]
pub struct PiholeClientRef {
    pub ip: String,
    pub name: Option<String>,
}

/// Reply object in Pi-hole v6 format.
#[derive(Debug, Serialize)]
pub struct PiholeReply {
    pub r#type: String,
    pub time: f64,
}

/// Extended DNS Error info.
#[derive(Debug, Serialize)]
pub struct PiholeEde {
    pub code: i32,
    pub text: Option<String>,
}

/// Single query entry in Pi-hole v6 format.
#[derive(Debug, Serialize)]
pub struct PiholeQueryEntry {
    pub id: i64,
    pub time: f64,
    pub r#type: String,
    pub domain: String,
    pub client: PiholeClientRef,
    pub status: &'static str,
    pub dnssec: String,
    pub reply: PiholeReply,
    pub upstream: String,
    /// Not yet tracked by Ferrous DNS.
    // TODO: populate from CNAME chain data when available
    pub cname: Option<String>,
    /// Not yet tracked by Ferrous DNS.
    // TODO: populate with blocklist ID when domain-to-list mapping is implemented
    pub list_id: Option<i64>,
    pub ede: PiholeEde,
}

/// Pi-hole v6 GET /api/queries/suggestions response.
///
/// Categories are returned flat at root level (no wrapper object).
#[derive(Debug, Serialize)]
pub struct SuggestionsResponse {
    pub domain: Vec<String>,
    pub client_ip: Vec<String>,
    pub client_name: Vec<String>,
    pub upstream: Vec<String>,
    pub r#type: Vec<String>,
    pub status: Vec<String>,
    pub reply: Vec<String>,
    pub dnssec: Vec<String>,
}

/// Maps Ferrous query log fields to Pi-hole v6 status strings.
pub(crate) fn map_query_status(
    blocked: bool,
    cache_hit: bool,
    block_source: Option<&BlockSource>,
) -> &'static str {
    if blocked {
        match block_source {
            Some(BlockSource::RegexFilter) => "REGEX",
            Some(BlockSource::ManagedDomain) => "DENYLIST",
            Some(BlockSource::CnameCloaking) => "GRAVITY_CNAME",
            _ => "GRAVITY",
        }
    } else if cache_hit {
        "CACHE"
    } else {
        "FORWARDED"
    }
}
