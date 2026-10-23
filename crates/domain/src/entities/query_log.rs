use super::block_source::BlockSource;
use crate::config::BlockResponseMode;
use crate::dns_record::RecordType;
use crate::DomainError;
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
    /// DNSSEC validation outcome filter.
    pub dnssec_status: Option<DnssecStatusFilter>,
    /// `Some(true)` keeps only DNS64-synthesized AAAA answers, `Some(false)`
    /// only non-synthesized rows; `None` does not filter.
    pub dns64_synthesized: Option<bool>,
    /// Exact match on the transport the client used to reach the resolver.
    pub protocol: Option<ClientProtocol>,
    /// Only queries logged before this Unix time.
    pub until: Option<i64>,
    /// Record types left out.
    pub excluded_record_types: Vec<RecordType>,
    /// Only queries answered with this kind of reply.
    pub reply: Option<ReplyFilter>,
}

/// What a logged query was answered with, as far as the log tells; see
/// [`QueryLog::reply_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    Ip,
    NoData,
    NxDomain,
    Cname,
    Refused,
    ServFail,
    /// No reply came.
    NoReply,
    Other,
    Unknown,
}

impl ReplyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplyKind::Ip => "IP",
            ReplyKind::NoData => "NODATA",
            ReplyKind::NxDomain => "NXDOMAIN",
            ReplyKind::Cname => "CNAME",
            ReplyKind::Refused => "REFUSED",
            ReplyKind::ServFail => "SERVFAIL",
            ReplyKind::NoReply => "NONE",
            ReplyKind::Other => "OTHER",
            ReplyKind::Unknown => "UNKNOWN",
        }
    }
}

impl FromStr for ReplyKind {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [
            ReplyKind::Ip,
            ReplyKind::NoData,
            ReplyKind::NxDomain,
            ReplyKind::Cname,
            ReplyKind::Refused,
            ReplyKind::ServFail,
            ReplyKind::NoReply,
            ReplyKind::Other,
            ReplyKind::Unknown,
        ]
        .into_iter()
        .find(|kind| kind.as_str().eq_ignore_ascii_case(s))
        .ok_or_else(|| DomainError::InvalidInput(format!("invalid reply kind: '{s}'")))
    }
}

/// Selects queries by [`ReplyKind`]. Blocked queries are classified under
/// `block_mode`, as [`QueryLog::reply_kind`] classifies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyFilter {
    pub kind: ReplyKind,
    pub block_mode: BlockResponseMode,
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
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allowed" => Ok(Self::Allowed),
            "blocked" => Ok(Self::Blocked),
            "cache" => Ok(Self::Cache),
            "upstream" => Ok(Self::Upstream),
            "rate-limited" => Ok(Self::RateLimited),
            "malware" => Ok(Self::Malware),
            other => Err(DomainError::InvalidInput(format!(
                "invalid query category: '{other}'"
            ))),
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
}

impl std::fmt::Display for QuerySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QuerySource {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client" => Ok(QuerySource::Client),
            "internal" => Ok(QuerySource::Internal),
            "dnssec_validation" => Ok(QuerySource::DnssecValidation),
            other => Err(DomainError::InvalidInput(format!(
                "invalid query source: '{other}'"
            ))),
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

impl FromStr for ClientProtocol {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(ClientProtocol::Udp),
            "tcp" => Ok(ClientProtocol::Tcp),
            "dot" => Ok(ClientProtocol::Dot),
            "doh" => Ok(ClientProtocol::Doh),
            "doq" => Ok(ClientProtocol::Doq),
            other => Err(DomainError::InvalidInput(format!(
                "invalid client protocol: '{other}'"
            ))),
        }
    }
}

/// A query's part in coalescing: identical queries in flight at the same time
/// share one upstream request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalescedRole {
    /// Identical queries that arrived while it was in flight shared its answer.
    Leader,
    /// It joined an identical query already in flight and got that query's
    /// answer, with no request of its own.
    Follower,
}

impl CoalescedRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            CoalescedRole::Leader => "leader",
            CoalescedRole::Follower => "follower",
        }
    }
}

impl std::fmt::Display for CoalescedRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CoalescedRole {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "leader" => Ok(CoalescedRole::Leader),
            "follower" => Ok(CoalescedRole::Follower),
            other => Err(DomainError::InvalidInput(format!(
                "invalid coalesced role: '{other}'"
            ))),
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
    pub dnssec_status: Option<DnssecStatus>,
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
    /// The query's part in coalescing, `None` when it took none.
    pub coalesced: Option<CoalescedRole>,
}

impl QueryLog {
    /// The kind of reply the query got, from what the log keeps of it:
    ///
    /// | Logged                                         | Kind |
    /// |------------------------------------------------|------|
    /// | blocked as an NXDOMAIN hijack                  | `NxDomain` |
    /// | rate limited (`RATE_LIMITED`)                  | `Refused` |
    /// | rate limited by truncation (`RATE_LIMITED_TC`) | `Other` |
    /// | any other block                                | what `block_mode` answers: `null_ip` → `Ip` for A/AAAA and `NoData` otherwise, `nxdomain` → `NxDomain`, `nodata` → `NoData`, `refused` → `Refused` |
    /// | `NOERROR` or `LOCAL_DNS` with addresses        | `Ip` |
    /// | `NOERROR` for A/AAAA without addresses         | `NoData` |
    /// | `NOERROR` for another type                     | `Other`: its records are not logged |
    /// | `LOCAL_DNS` without addresses                  | `Unknown`: a local NXDOMAIN and a non-address local answer log alike |
    /// | `SAFE_SEARCH`                                  | `Cname` |
    /// | `NXDOMAIN`, `SERVFAIL`, `REFUSED`              | the same |
    /// | `TIMEOUT`                                      | `NoReply` |
    /// | anything else                                  | `Unknown` |
    ///
    /// The query log repository mirrors this in SQL to filter on it; change
    /// both together.
    pub fn reply_kind(&self, block_mode: BlockResponseMode) -> ReplyKind {
        let has_addresses = self.answers.as_ref().is_some_and(|a| !a.is_empty());
        let is_address_query = matches!(self.record_type, RecordType::A | RecordType::AAAA);
        if self.blocked {
            return match (self.block_source, self.response_status) {
                (Some(BlockSource::NxdomainHijack), _) => ReplyKind::NxDomain,
                (_, Some("RATE_LIMITED")) => ReplyKind::Refused,
                (_, Some("RATE_LIMITED_TC")) => ReplyKind::Other,
                _ => match block_mode {
                    BlockResponseMode::NullIp if is_address_query => ReplyKind::Ip,
                    BlockResponseMode::NullIp | BlockResponseMode::NoData => ReplyKind::NoData,
                    BlockResponseMode::NxDomain => ReplyKind::NxDomain,
                    BlockResponseMode::Refused => ReplyKind::Refused,
                },
            };
        }
        match self.response_status {
            Some("NOERROR" | "LOCAL_DNS") if has_addresses => ReplyKind::Ip,
            Some("NOERROR") if is_address_query => ReplyKind::NoData,
            Some("NOERROR") => ReplyKind::Other,
            Some("SAFE_SEARCH") => ReplyKind::Cname,
            Some("NXDOMAIN") => ReplyKind::NxDomain,
            Some("SERVFAIL") => ReplyKind::ServFail,
            Some("REFUSED") => ReplyKind::Refused,
            Some("TIMEOUT") => ReplyKind::NoReply,
            _ => ReplyKind::Unknown,
        }
    }
}

#[derive(Debug, Clone, Default)]
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

/// Canonical DNSSEC validation outcome; `as_str` is the spelling persisted in
/// the query log's `dnssec_status` column.
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

    /// Validation could not show the answer `Secure` or provably `Insecure`.
    /// Strict mode refuses to serve these.
    pub fn is_unvalidated(&self) -> bool {
        matches!(self, Self::Bogus | Self::Indeterminate)
    }
}

impl FromStr for DnssecStatus {
    type Err = DomainError;

    /// Case-insensitive: storage uses `Secure` casing, HTTP filters lowercase.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [
            Self::Secure,
            Self::Insecure,
            Self::Bogus,
            Self::Indeterminate,
        ]
        .into_iter()
        .find(|status| status.as_str().eq_ignore_ascii_case(s))
        .ok_or_else(|| DomainError::InvalidInput(format!("invalid dnssec status: '{s}'")))
    }
}

/// Query-log filter on the DNSSEC validation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatusFilter {
    /// Every row that received a determination (non-NULL status).
    Any,
    Is(DnssecStatus),
    /// Rows that received no determination (NULL status). Not parsed from a
    /// string: Pi-hole's `dnssec=UNKNOWN` is its only source.
    NotValidated,
}

impl FromStr for DnssecStatusFilter {
    type Err = DomainError;

    /// `any` or one of the four outcomes, case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("any") {
            return Ok(Self::Any);
        }
        s.parse::<DnssecStatus>().map(Self::Is).map_err(|_| {
            DomainError::InvalidInput(format!(
                "invalid dnssec status filter: '{s}' (expected any, secure, insecure, bogus or indeterminate)"
            ))
        })
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

        let ranked = self.top_types(usize::MAX);
        self.most_queried_type = ranked.first().map(|(record_type, _)| *record_type);

        let total: u64 = ranked.iter().map(|(_, count)| count).sum();
        self.record_type_distribution = if total > 0 {
            ranked
                .into_iter()
                .map(|(record_type, count)| {
                    let percentage = (count as f64 / total as f64) * 100.0;
                    (record_type, percentage)
                })
                .collect()
        } else {
            Vec::new()
        };

        self
    }

    /// Most queried first; ties break by type name so the order is stable.
    pub fn top_types(&self, n: usize) -> Vec<(RecordType, u64)> {
        let mut types: Vec<(RecordType, u64)> = self
            .queries_by_type
            .iter()
            .map(|(rt, count)| (*rt, *count))
            .collect();

        types.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.as_str().cmp(b.0.as_str())));
        types.truncate(n);
        types
    }
}
