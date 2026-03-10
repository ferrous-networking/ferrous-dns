use ferrous_dns_domain::BlockSource;
use serde::Serialize;

/// Pi-hole v6 GET /api/queries response.
#[derive(Debug, Serialize)]
pub struct QueriesResponse {
    pub queries: Vec<PiholeQueryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<i64>,
    #[serde(rename = "recordsTotal")]
    pub records_total: u64,
    #[serde(rename = "recordsFiltered")]
    pub records_filtered: u64,
}

/// Client reference returned inside a query entry.
#[derive(Debug, Serialize)]
pub struct PiholeClientRef {
    pub ip: String,
    pub name: String,
}

/// Single query entry in Pi-hole v6 format.
#[derive(Debug, Serialize)]
pub struct PiholeQueryEntry {
    pub id: i64,
    pub time: f64,
    pub r#type: String,
    pub domain: String,
    pub client: PiholeClientRef,
    pub status: u8,
    pub dnssec: String,
    pub reply: String,
    pub response_time: f64,
    pub upstream: String,
}

/// Pi-hole v6 GET /api/queries/suggestions response.
#[derive(Debug, Serialize)]
pub struct SuggestionsResponse {
    pub suggestions: Vec<String>,
}

/// Maps Ferrous query log fields to Pi-hole v6 status codes.
///
/// Pi-hole status codes:
/// - 1 = blocked (gravity)
/// - 2 = allowed (forwarded)
/// - 3 = allowed (cache)
/// - 4 = blocked (regex)
/// - 5 = blocked (exact)
/// - 8 = allowed (CNAME)
/// - 9 = blocked (CNAME)
pub fn map_query_status(blocked: bool, cache_hit: bool, block_source: Option<&BlockSource>) -> u8 {
    if blocked {
        match block_source {
            Some(BlockSource::RegexFilter) => 4,
            Some(BlockSource::ManagedDomain) => 5,
            Some(BlockSource::CnameCloaking) => 9,
            Some(BlockSource::Blocklist) => 1,
            Some(BlockSource::Schedule) => 1,
            Some(BlockSource::DnsRebinding) => 1,
            Some(BlockSource::RateLimit) => 1,
            Some(BlockSource::DnsTunneling) => 1,
            None => 1,
        }
    } else if cache_hit {
        3
    } else {
        2
    }
}
