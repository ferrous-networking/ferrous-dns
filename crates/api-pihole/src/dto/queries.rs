use ferrous_dns_domain::{BlockSource, QueryLog};
use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/queries response.
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeClientRef {
    pub ip: String,
    pub name: Option<String>,
}

/// Reply object in Pi-hole v6 format.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeReply {
    pub r#type: String,
    pub time: f64,
}

/// Extended DNS Error info.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeEde {
    pub code: i32,
    pub text: Option<String>,
}

/// Single query entry in Pi-hole v6 format.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeQueryEntry {
    pub id: i64,
    pub time: f64,
    pub r#type: String,
    pub domain: String,
    pub client: PiholeClientRef,
    #[schema(value_type = String)]
    pub status: &'static str,
    pub dnssec: String,
    pub reply: PiholeReply,
    pub upstream: String,
    /// Not yet tracked by Ferrous DNS.
    pub cname: Option<String>,
    /// Not yet tracked by Ferrous DNS.
    pub list_id: Option<i64>,
    pub ede: PiholeEde,
}

/// Pi-hole v6 GET /api/queries/suggestions response.
///
/// Categories are returned flat at root level (no wrapper object).
#[derive(Debug, Serialize, ToSchema)]
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

/// Maps a Ferrous query log entry to its Pi-hole v6 status string.
pub(crate) fn map_query_status(q: &QueryLog) -> &'static str {
    if !q.blocked {
        return if q.cache_hit { "CACHE" } else { "FORWARDED" };
    }
    blocked_status(q.block_source)
}

/// The Pi-hole v6 status of a query blocked by `source`.
pub(crate) fn blocked_status(source: Option<BlockSource>) -> &'static str {
    match source {
        Some(BlockSource::RegexFilter) => "REGEX",
        Some(BlockSource::ManagedDomain) => "DENYLIST",
        Some(BlockSource::CnameCloaking) => "GRAVITY_CNAME",
        Some(
            BlockSource::Blocklist
            | BlockSource::Schedule
            | BlockSource::DnsRebinding
            | BlockSource::RateLimit
            | BlockSource::DnsTunneling
            | BlockSource::NxdomainHijack
            | BlockSource::ResponseIpFilter
            | BlockSource::DgaDetection,
        )
        | None => "GRAVITY",
    }
}
