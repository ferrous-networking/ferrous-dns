use serde::Serialize;
use std::collections::HashMap;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/stats/summary response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SummaryResponse {
    pub queries: QuerySummary,
    pub clients: ClientSummary,
    pub gravity: GravitySummary,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuerySummary {
    pub total: u64,
    pub blocked: u64,
    pub percent_blocked: f64,
    pub unique_domains: u64,
    pub forwarded: u64,
    pub cached: u64,
    pub frequency: f64,
    pub types: QueryTypeCounts,
    pub status: QueryStatusCounts,
    pub replies: ReplyTypeCounts,
}

/// Queries per DNS type over FTL's fixed key set; any other type counts as
/// `OTHER`.
#[derive(Debug, Default, Serialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub struct QueryTypeCounts {
    pub a: u64,
    pub aaaa: u64,
    pub any: u64,
    pub srv: u64,
    pub soa: u64,
    pub ptr: u64,
    pub txt: u64,
    pub naptr: u64,
    pub mx: u64,
    pub ds: u64,
    pub rrsig: u64,
    pub dnskey: u64,
    pub ns: u64,
    pub svcb: u64,
    pub https: u64,
    pub other: u64,
}

impl QueryTypeCounts {
    pub fn add(&mut self, record_type: &str, count: u64) {
        let slot = match record_type {
            "A" => &mut self.a,
            "AAAA" => &mut self.aaaa,
            "ANY" => &mut self.any,
            "SRV" => &mut self.srv,
            "SOA" => &mut self.soa,
            "PTR" => &mut self.ptr,
            "TXT" => &mut self.txt,
            "NAPTR" => &mut self.naptr,
            "MX" => &mut self.mx,
            "DS" => &mut self.ds,
            "RRSIG" => &mut self.rrsig,
            "DNSKEY" => &mut self.dnskey,
            "NS" => &mut self.ns,
            "SVCB" => &mut self.svcb,
            "HTTPS" => &mut self.https,
            _ => &mut self.other,
        };
        *slot += count;
    }
}

/// Queries per FTL query status (the `status` of a `/queries` entry).
#[derive(Debug, Default, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct QueryStatusCounts {
    pub unknown: u64,
    pub gravity: u64,
    pub forwarded: u64,
    pub cache: u64,
    pub regex: u64,
    pub denylist: u64,
    pub external_blocked_ip: u64,
    pub external_blocked_null: u64,
    pub external_blocked_nxra: u64,
    pub gravity_cname: u64,
    pub regex_cname: u64,
    pub denylist_cname: u64,
    pub retried: u64,
    pub retried_dnssec: u64,
    pub in_progress: u64,
    pub dbbusy: u64,
    pub special_domain: u64,
    pub cache_stale: u64,
    pub external_blocked_ede15: u64,
}

impl QueryStatusCounts {
    /// Adds `count` under one of the status names Ferrous produces.
    pub fn add(&mut self, status: &str, count: u64) {
        let slot = match status {
            "GRAVITY" => &mut self.gravity,
            "FORWARDED" => &mut self.forwarded,
            "CACHE" => &mut self.cache,
            "REGEX" => &mut self.regex,
            "DENYLIST" => &mut self.denylist,
            "GRAVITY_CNAME" => &mut self.gravity_cname,
            _ => &mut self.unknown,
        };
        *slot += count;
    }
}

/// Queries per FTL reply type. Ferrous does not aggregate reply types, so
/// every counter stays 0.
#[derive(Debug, Default, Serialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub struct ReplyTypeCounts {
    pub unknown: u64,
    pub nodata: u64,
    pub nxdomain: u64,
    pub cname: u64,
    pub ip: u64,
    pub domain: u64,
    pub rrname: u64,
    pub servfail: u64,
    pub refused: u64,
    pub notimp: u64,
    pub other: u64,
    pub dnssec: u64,
    pub none: u64,
    pub blob: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSummary {
    pub active: u64,
    pub total: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GravitySummary {
    pub domains_being_blocked: u64,
    pub last_update: i64,
}

/// Pi-hole v6 GET /api/stats/history response.
///
/// Each bucket covers 10 minutes. The full 24h window yields 144 buckets.
#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryResponse {
    pub history: Vec<HistoryBucket>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryBucket {
    pub timestamp: i64,
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub forwarded: u64,
}

/// Pi-hole v6 GET /api/stats/top_domains response (also used for top_blocked).
#[derive(Debug, Serialize, ToSchema)]
pub struct TopDomainsResponse {
    pub domains: Vec<TopDomainEntry>,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

/// Single entry in the top domains array.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopDomainEntry {
    pub domain: String,
    pub count: u64,
}

/// Pi-hole v6 GET /api/stats/top_clients response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopClientsResponse {
    pub clients: Vec<TopClientEntry>,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

/// Single entry in the top clients array.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopClientEntry {
    pub ip: String,
    pub name: String,
    pub count: u64,
}

/// Pi-hole v6 GET /api/stats/query_types response.
#[derive(Debug, Serialize, ToSchema)]
pub struct QueryTypesResponse {
    /// Keys are DNS record type names (e.g. "A", "AAAA", "MX").
    /// Values are percentages (0.0-100.0).
    pub querytypes: HashMap<String, f64>,
}

/// Pi-hole v6 GET /api/stats/recent_blocked response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecentBlockedResponse {
    pub domain: Option<String>,
}
