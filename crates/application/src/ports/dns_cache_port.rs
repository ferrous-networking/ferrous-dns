use ferrous_dns_domain::{DnssecStatus, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

/// Snapshot of DNS cache metrics for API exposure.
#[derive(Debug, Clone)]
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
    pub batch_evictions: u64,
    pub hit_rate: f64,
    /// Phase 6: upstream failures classified as transient (timeout, refused,
    /// reset, no healthy servers, invalid response, etc.) and therefore NOT
    /// cached as NXDOMAIN. Helps operators diagnose upstream instability.
    pub transient_upstream_errors: u64,
}

/// Snapshot of a single positive cache entry, as listed by the admin UI.
#[derive(Debug, Clone)]
pub struct CacheEntrySnapshot {
    pub domain: String,
    pub record_type: RecordType,
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
    /// Hits served from the shared cache. Lookups absorbed by the per-thread
    /// L1 cache are not counted here.
    pub hits: u64,
    pub last_access_secs: u64,
    pub is_permanent: bool,
    /// Past its TTL but still served within the stale grace period.
    pub is_stale: bool,
}

/// Field the cache listing is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheEntrySort {
    Hits,
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

/// Port for DNS cache operations exposed to the API layer.
pub trait DnsCachePort: Send + Sync {
    fn cache_size(&self) -> usize;
    fn cache_metrics_snapshot(&self) -> CacheMetricsSnapshot;
    fn insert_permanent_record(
        &self,
        domain: &str,
        record_type: RecordType,
        addresses: Vec<IpAddr>,
    );
    fn remove_record(&self, domain: &str, record_type: &RecordType) -> bool;
    fn list_entries(&self, query: &CacheEntryQuery) -> CacheEntryPage;
}
