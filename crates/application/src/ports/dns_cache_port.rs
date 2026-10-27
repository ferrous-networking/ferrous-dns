use ferrous_dns_domain::{DnssecStatus, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

/// Snapshot of DNS cache metrics for API exposure.
#[derive(Debug, Clone, Default)]
pub struct CacheMetricsSnapshot {
    pub total_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub optimistic_refreshes: u64,
    pub stale_hits: u64,
    pub lazy_deletions: u64,
    pub compactions: u64,
    /// Positive entries removed past their TTL, since start. Unlike
    /// `compactions`, negative answers are not counted, as in `insertions`.
    pub expirations: u64,
    pub batch_evictions: u64,
    pub hit_rate: f64,
    /// Upstream failures classified as transient (timeout, refused, reset, no
    /// healthy servers, invalid response, etc.) and therefore NOT cached as NXDOMAIN.
    pub transient_upstream_errors: u64,
    /// Serve-stale repairs dropped because the stale queue was full. A client
    /// got a stale answer with no renewal scheduled behind it.
    pub stale_refresh_drops: u64,
    /// Renewals ahead of expiry given up on: a due entry that died waiting
    /// for a permit.
    pub optimistic_refresh_shed: u64,
}

/// Snapshot of a single positive cache entry, as listed by the admin UI.
#[derive(Debug, Clone)]
pub struct CacheEntrySnapshot {
    pub domain: String,
    pub record_type: RecordType,
    /// The client group whose own view holds the entry: a split-horizon
    /// answer from a pool routed for that group. `None` for the view every
    /// client shares.
    pub group_id: Option<i64>,
    /// Addresses for A/AAAA entries; empty for every other record type.
    pub answers: Vec<IpAddr>,
    /// Target of a CNAME entry.
    pub canonical_name: Option<String>,
    /// `None` when the entry was cached without a DNSSEC determination.
    pub dnssec_status: Option<DnssecStatus>,
    pub ttl: u32,
    /// Seconds left before expiry; `None` for permanent entries.
    pub remaining_ttl: Option<u32>,
    pub cached_at_secs: u64,
    pub expires_at_secs: u64,
    /// Hits served from the cache, per-thread L1 hits included; L1 hands
    /// them over in batches, so the count can trail by the last second.
    pub hits: u64,
    /// Times the entry was renewed from upstream since it was stored.
    pub refreshes: u64,
    pub last_access_secs: u64,
    pub is_permanent: bool,
    /// Past its TTL but still served within the stale grace period.
    pub is_stale: bool,
}

/// Field the cache listing is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheEntrySort {
    Hits,
    Refreshes,
    #[default]
    CachedAt,
    ExpiresAt,
    Domain,
    Type,
}

impl FromStr for CacheEntrySort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hits" => Ok(Self::Hits),
            "refreshes" => Ok(Self::Refreshes),
            "cached_at" => Ok(Self::CachedAt),
            "expires_at" => Ok(Self::ExpiresAt),
            "domain" => Ok(Self::Domain),
            "type" => Ok(Self::Type),
            other => Err(format!("invalid cache entry sort: '{other}'")),
        }
    }
}

/// Direction the cache listing is ordered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheEntryOrder {
    Asc,
    #[default]
    Desc,
}

impl FromStr for CacheEntryOrder {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "asc" => Ok(Self::Asc),
            "desc" => Ok(Self::Desc),
            other => Err(format!("invalid cache entry order: '{other}'")),
        }
    }
}

/// Filtering, ordering and pagination for a cache listing.
#[derive(Debug, Clone)]
pub struct CacheEntryQuery {
    /// Case-insensitive substring match on the cached domain.
    pub domain: Option<String>,
    pub record_type: Option<RecordType>,
    pub sort: CacheEntrySort,
    pub order: CacheEntryOrder,
    pub limit: usize,
    pub offset: usize,
}

impl Default for CacheEntryQuery {
    fn default() -> Self {
        Self {
            domain: None,
            record_type: None,
            sort: CacheEntrySort::default(),
            order: CacheEntryOrder::default(),
            limit: 25,
            offset: 0,
        }
    }
}

/// One page of cache entries plus the counts needed by the UI.
#[derive(Debug, Clone)]
pub struct CacheEntryPage {
    pub entries: Vec<CacheEntrySnapshot>,
    /// Entries matching the filter, before pagination is applied.
    pub total: usize,
    /// Entries in the cache, ignoring the filter.
    pub records_total: usize,
}

/// A cache entry among the most renewed ones.
#[derive(Debug, Clone)]
pub struct CacheTopRefreshed {
    pub domain: String,
    pub record_type: RecordType,
    /// Times the entry was renewed from upstream since it was stored.
    pub refreshes: u64,
}

/// What one pass over the positive cache tells the dashboard about renewal
/// and expiry.
#[derive(Debug, Clone, Default)]
pub struct CacheOverview {
    /// Entries renewed at least once, most renewed first; ties ordered by
    /// domain, then record type, as the listing orders them.
    pub top_refreshed: Vec<CacheTopRefreshed>,
    /// Entries still within their TTL whose TTL ends inside the window.
    pub expiring_soon: usize,
}

/// Port for DNS cache operations exposed to the API layer.
pub trait DnsCachePort: Send + Sync {
    fn cache_size(&self) -> usize;
    fn cache_metrics_snapshot(&self) -> CacheMetricsSnapshot;
    fn insert_permanent_record(
        &self,
        domain: &str,
        record_type: RecordType,
        addresses: Vec<IpAddr>,
        ttl: u32,
    );
    /// Removes the entry from `group_id`'s own view, or from the view every
    /// client shares when `None`, where every local record lives.
    fn remove_record(&self, domain: &str, record_type: &RecordType, group_id: Option<i64>) -> bool;
    /// Whether the entry is permanent — a local DNS record, not a cached
    /// upstream answer. Nothing reloads a permanent entry once it is removed,
    /// so callers that expose eviction to users need to know the difference.
    fn is_permanent_record(&self, domain: &str, record_type: &RecordType) -> bool;
    fn list_entries(&self, query: &CacheEntryQuery) -> CacheEntryPage;
    /// The `top` most renewed entries and how many entries expire within
    /// `expiring_within_secs`, in one pass that copies only the top entries.
    fn cache_overview(&self, top: usize, expiring_within_secs: u64) -> CacheOverview;
}
