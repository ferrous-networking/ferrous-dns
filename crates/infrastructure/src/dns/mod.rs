pub mod cache;
pub mod cache_updater;
pub mod cache_warming;
pub mod prefetch;
pub mod resolver;
pub mod server;

// Re-export from refactored cache module (SOLID compliant ✅)
pub use cache::{
    CacheKey, CacheMetrics, CachedData, CachedRecord, DnsCache, DnssecStatus, EvictionStrategy,
};
pub use cache_updater::CacheUpdater;
pub use cache_warming::{CacheWarmer, WarmingStats};
pub use prefetch::PrefetchPredictor;
pub use resolver::HickoryDnsResolver;
