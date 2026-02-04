// Cache module - Refactored following SOLID principles

pub mod data;
pub mod eviction;
pub mod key;
pub mod metrics;
pub mod record;
pub mod storage;

pub use data::{CachedData, DnssecStatus};
pub use eviction::{EvictionEntry, EvictionStrategy};
pub use key::{BorrowedKey, CacheKey};
pub use metrics::CacheMetrics;
pub use record::CachedRecord;
pub use storage::DnsCache;
