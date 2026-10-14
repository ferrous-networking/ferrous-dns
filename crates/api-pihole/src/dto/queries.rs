use ferrous_dns_domain::{
    BlockSource, DnsProtocol, DnssecStatus, QueryLog, RecordType, UpstreamAddr,
};
use serde::Serialize;
use std::borrow::Cow;
use utoipa::ToSchema;

/// FTL's query type names, in `enum query_type` order (FTL `enums.h`) from
/// `TYPE_A`: what `/queries/suggestions` lists and `?type=` accepts.
pub(crate) const FTL_QUERY_TYPES: [&str; 16] = [
    "A", "AAAA", "ANY", "SRV", "SOA", "PTR", "TXT", "NAPTR", "MX", "DS", "RRSIG", "DNSKEY", "NS",
    "OTHER", "SVCB", "HTTPS",
];

/// FTL's query statuses, in `enum query_status` order.
pub(crate) const FTL_QUERY_STATUSES: [&str; 19] = [
    "UNKNOWN",
    "GRAVITY",
    "FORWARDED",
    "CACHE",
    "REGEX",
    "DENYLIST",
    "EXTERNAL_BLOCKED_IP",
    "EXTERNAL_BLOCKED_NULL",
    "EXTERNAL_BLOCKED_NXRA",
    "GRAVITY_CNAME",
    "REGEX_CNAME",
    "DENYLIST_CNAME",
    "RETRIED",
    "RETRIED_DNSSEC",
    "IN_PROGRESS",
    "DBBUSY",
    "SPECIAL_DOMAIN",
    "CACHE_STALE",
    "EXTERNAL_BLOCKED_EDE15",
];

/// FTL's reply types, in `enum reply_type` order.
pub(crate) const FTL_REPLY_TYPES: [&str; 14] = [
    "UNKNOWN", "NODATA", "NXDOMAIN", "CNAME", "IP", "DOMAIN", "RRNAME", "SERVFAIL", "REFUSED",
    "NOTIMP", "OTHER", "DNSSEC", "NONE", "BLOB",
];

/// FTL's DNSSEC statuses, in `enum dnssec_status` order.
pub(crate) const FTL_DNSSEC_STATUSES: [&str; 6] = [
    "UNKNOWN",
    "SECURE",
    "INSECURE",
    "BOGUS",
    "ABANDONED",
    "TRUNCATED",
];

/// Pi-hole v6 GET /api/queries response.
#[derive(Debug, Serialize, ToSchema)]
pub struct QueriesResponse {
    pub queries: Vec<PiholeQueryEntry>,
    /// Id of the newest query the pages are pinned to; send it back with
    /// `start` to page through the same snapshot.
    pub cursor: i64,
    #[serde(rename = "recordsTotal")]
    pub records_total: u64,
    #[serde(rename = "recordsFiltered")]
    pub records_filtered: u64,
    /// DataTables draw counter, echoed (0 when not sent).
    pub draw: i64,
    /// Unix time of the oldest query of the last 24 hours, 0 when none.
    pub earliest_timestamp: f64,
    /// Unix time of the oldest stored query, 0 when none.
    pub earliest_timestamp_disk: f64,
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
    #[schema(value_type = String)]
    pub r#type: &'static str,
    /// Seconds the answer took.
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
    #[schema(value_type = String)]
    pub dnssec: &'static str,
    pub reply: PiholeReply,
    /// `ip#port` of the server that answered, `null` when none did.
    pub upstream: Option<String>,
    /// Not yet tracked by Ferrous DNS.
    pub cname: Option<String>,
    /// Not yet tracked by Ferrous DNS.
    pub list_id: Option<i64>,
    pub ede: PiholeEde,
}

/// Pi-hole v6 GET /api/queries/suggestions response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SuggestionsResponse {
    pub suggestions: QuerySuggestions,
}

/// Values the query log can be filtered by.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuerySuggestions {
    pub domain: Vec<String>,
    pub client_ip: Vec<String>,
    pub client_name: Vec<String>,
    pub upstream: Vec<String>,
    pub r#type: Vec<String>,
    pub status: Vec<String>,
    pub reply: Vec<String>,
    pub dnssec: Vec<String>,
}

/// Maps a Ferrous query log entry to its Pi-hole v6 status string. Answers
/// from local configuration are `CACHE`, as FTL counts them.
pub(crate) fn map_query_status(q: &QueryLog) -> &'static str {
    if q.blocked {
        return blocked_status(q.block_source);
    }
    if q.cache_hit || q.response_status == Some("LOCAL_DNS") {
        "CACHE"
    } else {
        "FORWARDED"
    }
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

/// The FTL type name of `record_type`; a type outside FTL's list is
/// `TYPE<number>`, as FTL prints its `TYPE_OTHER` queries.
pub(crate) fn query_type_name(record_type: RecordType) -> Cow<'static, str> {
    let name = record_type.as_str();
    if FTL_QUERY_TYPES.contains(&name) {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("TYPE{}", record_type.to_u16()))
    }
}

/// The FTL name of a DNSSEC outcome. `Indeterminate` (validation could not
/// complete) is `ABANDONED`, FTL's status for a validation that gave up; a
/// query never validated is `UNKNOWN`.
pub(crate) fn dnssec_name(status: Option<DnssecStatus>) -> &'static str {
    match status {
        Some(DnssecStatus::Secure) => "SECURE",
        Some(DnssecStatus::Insecure) => "INSECURE",
        Some(DnssecStatus::Bogus) => "BOGUS",
        Some(DnssecStatus::Indeterminate) => "ABANDONED",
        None => "UNKNOWN",
    }
}

/// FTL's `ip#port` for an upstream server URL the query log records, e.g.
/// `udp://1.1.1.1:53` → `1.1.1.1#53`. A server known only by name (DoH, or
/// not yet resolved) gives `name#port`; one that no longer parses is kept
/// as recorded.
pub(crate) fn forward_address(server: &str) -> String {
    match server.parse::<DnsProtocol>() {
        Ok(protocol) => format!("{}#{}", upstream_host(&protocol), upstream_port(&protocol)),
        Err(_) => server.to_string(),
    }
}

/// Port an upstream server is reached on.
pub(crate) fn upstream_port(protocol: &DnsProtocol) -> u16 {
    match protocol {
        DnsProtocol::Udp { addr }
        | DnsProtocol::Tcp { addr }
        | DnsProtocol::Tls { addr, .. }
        | DnsProtocol::Quic { addr, .. } => addr.port(),
        DnsProtocol::Https { port, .. } | DnsProtocol::H3 { port, .. } => *port,
    }
}

/// The IP an upstream server is reached at, or its name when it has no IP.
fn upstream_host(protocol: &DnsProtocol) -> String {
    match protocol {
        DnsProtocol::Udp { addr }
        | DnsProtocol::Tcp { addr }
        | DnsProtocol::Tls { addr, .. }
        | DnsProtocol::Quic { addr, .. } => match addr {
            UpstreamAddr::Resolved(socket) => socket.ip().to_string(),
            UpstreamAddr::Unresolved { hostname, .. } => hostname.to_string(),
        },
        DnsProtocol::Https { hostname, .. } | DnsProtocol::H3 { hostname, .. } => {
            hostname.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_address_is_ftls_ip_hash_port() {
        assert_eq!(forward_address("udp://1.1.1.1:53"), "1.1.1.1#53");
        assert_eq!(forward_address("tcp://[2001:db8::1]:53"), "2001:db8::1#53");
        assert_eq!(forward_address("tls://dns.google:853"), "dns.google#853");
        assert_eq!(
            forward_address("https://dns.google/dns-query"),
            "dns.google#443"
        );
        assert_eq!(forward_address("not a server"), "not a server");
    }
}
