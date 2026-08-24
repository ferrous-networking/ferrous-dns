use super::block_source::BlockSource;
use crate::dns_record::RecordType;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Filter criteria for paginated query log queries.
///
/// All fields are optional — `None` means no filter for that dimension.
/// Multiple active filters are combined with AND logic.
#[derive(Debug, Clone, Default)]
pub struct QueryLogFilter {
    /// Substring match on domain (SQL `LIKE %domain%`).
    pub domain: Option<String>,
    /// Query category (allowed, blocked, cache, upstream, etc.).
    pub category: Option<QueryCategory>,
    /// Substring match on client IP or hostname (SQL `LIKE`).
    pub client: Option<String>,
    /// Exact match on DNS record type.
    pub record_type: Option<RecordType>,
    /// Exact match on upstream server address.
    pub upstream: Option<String>,
    /// DNSSEC validation status filter. The sentinel `"any"` matches every
    /// row that received a determination (non-NULL status); any other value
    /// is an exact match on the stored status string.
    pub dnssec_status: Option<String>,
    /// `Some(true)` keeps only DNS64-synthesized AAAA answers, `Some(false)`
    /// only non-synthesized rows; `None` does not filter.
    pub dns64_synthesized: Option<bool>,
    /// Exact match on the transport the client used to reach the resolver.
    pub protocol: Option<ClientProtocol>,
}

/// Category filter for query log pagination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryCategory {
    Allowed,
    Blocked,
    Cache,
    Upstream,
    RateLimited,
    Malware,
}

impl FromStr for QueryCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allowed" => Ok(Self::Allowed),
            "blocked" => Ok(Self::Blocked),
            "cache" => Ok(Self::Cache),
            "upstream" => Ok(Self::Upstream),
            "rate-limited" => Ok(Self::RateLimited),
            "malware" => Ok(Self::Malware),
            other => Err(format!("invalid query category: '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuerySource {
    #[default]
    Client,
    Internal,
    DnssecValidation,
}

impl QuerySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuerySource::Client => "client",
            QuerySource::Internal => "internal",
            QuerySource::DnssecValidation => "dnssec_validation",
        }
    }

    pub fn is_internal(&self) -> bool {
        matches!(self, QuerySource::Internal | QuerySource::DnssecValidation)
    }
}

impl std::fmt::Display for QuerySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct ParseQuerySourceError {
    invalid: String,
}

impl std::fmt::Display for ParseQuerySourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid query source: '{}'", self.invalid)
    }
}

impl std::error::Error for ParseQuerySourceError {}

impl FromStr for QuerySource {
    type Err = ParseQuerySourceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client" => Ok(QuerySource::Client),
            "internal" => Ok(QuerySource::Internal),
            "dnssec_validation" => Ok(QuerySource::DnssecValidation),
            _ => Err(ParseQuerySourceError {
                invalid: s.to_string(),
            }),
        }
    }
}

/// Transport a client used to reach the resolver.
///
/// Covers the five inbound listeners only; the upstream side is described by
/// [`crate::DnsProtocol`], which carries an address and is a different concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocol {
    Udp,
    Tcp,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS (RFC 8484).
    Doh,
    /// DNS over QUIC (RFC 9250).
    Doq,
}

impl ClientProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientProtocol::Udp => "udp",
            ClientProtocol::Tcp => "tcp",
            ClientProtocol::Dot => "dot",
            ClientProtocol::Doh => "doh",
            ClientProtocol::Doq => "doq",
        }
    }
}

impl std::fmt::Display for ClientProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct ParseClientProtocolError {
    invalid: String,
}

impl std::fmt::Display for ParseClientProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid client protocol: '{}'", self.invalid)
    }
}

impl std::error::Error for ParseClientProtocolError {}

impl FromStr for ClientProtocol {
    type Err = ParseClientProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(ClientProtocol::Udp),
            "tcp" => Ok(ClientProtocol::Tcp),
            "dot" => Ok(ClientProtocol::Dot),
            "doh" => Ok(ClientProtocol::Doh),
            "doq" => Ok(ClientProtocol::Doq),
            _ => Err(ParseClientProtocolError {
                invalid: s.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryLog {
    pub id: Option<i64>,
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub client_hostname: Option<Arc<str>>,
    pub blocked: bool,
    pub response_time_us: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,
    pub dnssec_status: Option<&'static str>,
    /// `true` when the AAAA answer was synthesized by DNS64 (RFC 6147).
    pub dns64_synthesized: bool,
    /// Resolved A/AAAA addresses of the answer. `None` for blocked queries and
    /// for record types that carry no address answer. Only the first few are
    /// persisted (see `MAX_LOGGED_ANSWERS` in the query log writer).
    pub answers: Option<Arc<Vec<IpAddr>>>,
    pub upstream_server: Option<Arc<str>>,
    pub upstream_pool: Option<Arc<str>>,
    pub response_status: Option<&'static str>,
    pub timestamp: Option<String>,

    pub query_source: QuerySource,

    /// Transport the client used. `None` for internally generated queries and
    /// for rows written before the column existed.
    pub protocol: Option<ClientProtocol>,

    pub group_id: Option<i64>,
    pub block_source: Option<BlockSource>,
}

#[derive(Debug, Clone)]
pub struct QueryStats {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub queries_rate_limited: u64,
    pub queries_malware_detected: u64,
    /// Queries whose DNSSEC validation returned Bogus (whether served under
    /// Permissive or SERVFAIL'd under Strict).
    pub queries_dnssec_bogus: u64,
    /// AAAA answers synthesized by DNS64 (RFC 6147).
    pub queries_dns64_synthesized: u64,
    pub unique_clients: u64,
    pub uptime_seconds: u64,
    pub cache_hit_rate: f64,
    pub avg_query_time_ms: f64,
    pub avg_cache_time_ms: f64,
    pub avg_upstream_time_ms: f64,

    pub source_stats: HashMap<String, u64>,

    pub queries_by_type: HashMap<RecordType, u64>,
    pub most_queried_type: Option<RecordType>,
    pub record_type_distribution: Vec<(RecordType, f64)>,
}

/// Canonical DNSSEC validation outcome. This is the single source of truth for
/// the status strings persisted in the query log (`dnssec_status` column) and
/// threaded through `DnsResolution`. Control-flow decisions (AD-bit gating,
/// Strict-mode SERVFAIL, cache suppression) compare against `as_str()` rather
/// than bare string literals, so a typo becomes a compile error instead of a
/// silently mis-gated security decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

impl DnssecStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        }
    }
}

impl FromStr for DnssecStatus {
    type Err = String;

    /// Case-insensitive parse of a status string (accepts both the canonical
    /// `Secure` casing used in storage and lowercase HTTP filter values).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "secure" => Ok(Self::Secure),
            "insecure" => Ok(Self::Insecure),
            "bogus" => Ok(Self::Bogus),
            "indeterminate" => Ok(Self::Indeterminate),
            other => Err(format!("invalid dnssec status: '{other}'")),
        }
    }
}

/// Aggregated DNSSEC validation outcome counts for a period, over client
/// queries only. `validated` counts queries that received a determination
/// (any non-NULL status) and equals the sum of `secure`, `insecure`, `bogus`
/// and `indeterminate`; `total` counts every client query and is the
/// denominator for validation coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnssecStats {
    pub total: u64,
    pub validated: u64,
    pub secure: u64,
    pub insecure: u64,
    pub bogus: u64,
    pub indeterminate: u64,
}

impl QueryStats {
    pub fn with_analytics(mut self, queries_by_type: HashMap<RecordType, u64>) -> Self {
        self.queries_by_type = queries_by_type;

        self.most_queried_type = self
            .queries_by_type
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(record_type, _)| *record_type);

        let total: u64 = self.queries_by_type.values().sum();

        if total > 0 {
            let mut distribution: Vec<(RecordType, f64)> = self
                .queries_by_type
                .iter()
                .map(|(record_type, count)| {
                    let percentage = (*count as f64 / total as f64) * 100.0;
                    (*record_type, percentage)
                })
                .collect();

            distribution.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            self.record_type_distribution = distribution;
        } else {
            self.record_type_distribution = Vec::new();
        }

        self
    }

    pub fn top_types(&self, n: usize) -> Vec<(RecordType, u64)> {
        let mut types: Vec<(RecordType, u64)> = self
            .queries_by_type
            .iter()
            .map(|(rt, count)| (*rt, *count))
            .collect();

        types.sort_by_key(|b| std::cmp::Reverse(b.1));
        types.truncate(n);
        types
    }

    pub fn type_percentage(&self, record_type: RecordType) -> f64 {
        self.record_type_distribution
            .iter()
            .find(|(rt, _)| *rt == record_type)
            .map(|(_, pct)| *pct)
            .unwrap_or(0.0)
    }

    pub fn type_count(&self, record_type: RecordType) -> u64 {
        *self.queries_by_type.get(&record_type).unwrap_or(&0)
    }
}

impl Default for QueryStats {
    fn default() -> Self {
        Self {
            queries_total: 0,
            queries_blocked: 0,
            queries_rate_limited: 0,
            queries_malware_detected: 0,
            queries_dnssec_bogus: 0,
            queries_dns64_synthesized: 0,
            unique_clients: 0,
            uptime_seconds: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
            source_stats: HashMap::new(),
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_updates: u64,
    pub total_evictions: u64,
    pub hit_rate: f64,
    pub avg_ttl_seconds: u64,
}
