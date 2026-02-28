pub mod block_filter;
pub mod cache;
pub mod cache_maintenance;
pub mod cache_warming;
pub mod dnssec;
pub mod events;
pub mod fast_path;
pub mod forwarding;
pub mod load_balancer;
pub mod prefetch;
pub mod query_logger;
pub mod resolver;
pub mod server;
pub mod transport;
pub mod wire_response;

pub use block_filter::BlockFilterEngine;
pub use cache::{
    CacheKey, CacheMetrics, CachedAddresses, CachedData, CachedRecord, DnsCache, DnsCacheAccess,
    DnsCacheConfig, DnssecStatus, EvictionStrategy, NegativeQueryTracker,
};
pub use cache_maintenance::DnsCacheMaintenance;
pub use cache_warming::{CacheWarmer, WarmingStats};
pub use events::{QueryEvent, QueryEventEmitter};
pub use load_balancer::{
    BalancedStrategy, FailoverStrategy, HealthChecker, ParallelStrategy, PoolManager, ServerHealth,
    ServerStatus, UpstreamHealthAdapter,
};
pub use prefetch::PrefetchPredictor;
pub use query_logger::QueryEventLogger;
pub use resolver::HickoryDnsResolver;
