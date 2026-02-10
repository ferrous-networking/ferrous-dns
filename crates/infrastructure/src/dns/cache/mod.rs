pub mod data;
pub mod eviction;
pub mod key;
pub mod metrics;
pub mod negative_ttl;
pub mod record;
pub mod storage;

pub use data::{CachedData, DnssecStatus};
pub use eviction::{EvictionEntry, EvictionStrategy};
pub use key::{BorrowedKey, CacheKey};
pub use metrics::CacheMetrics;
pub use negative_ttl::{NegativeQueryTracker, TrackerStats};
pub use record::CachedRecord;
pub use storage::DnsCache;
