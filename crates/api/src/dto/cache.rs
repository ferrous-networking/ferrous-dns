use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct CacheStatsQuery {
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_period() -> String {
    "24h".to_string()
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct CacheStatsResponse {
    pub total_entries: usize,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_refreshes: u64,
    pub hit_rate: f64,
    pub refresh_rate: f64,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct CacheMetricsResponse {
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
    pub transient_upstream_errors: u64,
}

#[derive(Deserialize, Debug, IntoParams)]
pub struct CacheEntriesQuery {
    #[serde(default = "default_entries_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    /// Case-insensitive substring match on the cached domain.
    pub domain: Option<String>,
    /// Record type name, e.g. `A`, `AAAA`, `CNAME`.
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    /// One of `hits`, `cached_at`, `expires_at`, `domain`, `type`.
    /// Defaults to `cached_at`.
    pub sort: Option<String>,
    /// `asc` or `desc`. Defaults to `desc`.
    pub order: Option<String>,
}

fn default_entries_limit() -> u32 {
    25
}

#[derive(Deserialize, Debug, IntoParams)]
pub struct DeleteCacheEntryQuery {
    pub domain: String,
    #[serde(rename = "type")]
    pub record_type: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct CacheEntryResponse {
    pub domain: String,
    #[serde(rename = "type")]
    #[schema(value_type = String)]
    pub record_type: &'static str,
    /// Addresses for A/AAAA entries; empty for every other record type.
    pub answers: Vec<String>,
    pub canonical_name: Option<String>,
    #[schema(value_type = Option<String>)]
    pub dnssec_status: Option<&'static str>,
    pub ttl: u32,
    /// Seconds left before expiry; `null` for permanent entries.
    pub remaining_ttl: Option<u32>,
    /// Unix epoch seconds when the entry was inserted.
    pub cached_at: u64,
    /// Unix epoch seconds when the entry expires; `null` for permanent entries.
    pub expires_at: Option<u64>,
    /// Hits served from the shared cache. Lookups absorbed by the per-thread
    /// L1 cache are not counted here.
    pub hits: u64,
    pub last_access: u64,
    pub permanent: bool,
    /// Past its TTL but still served within the stale grace period.
    pub stale: bool,
}

#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedCacheEntries {
    pub data: Vec<CacheEntryResponse>,
    /// Entries matching the applied filters.
    pub total: usize,
    /// Entries in the cache, ignoring the filters.
    pub records_total: usize,
    pub limit: u32,
    pub offset: u32,
}
