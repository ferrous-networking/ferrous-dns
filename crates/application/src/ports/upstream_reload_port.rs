use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, UpstreamPool};

/// Port for hot-swapping the live upstream DNS pools without restarting the server.
///
/// Implementations rebuild the running pool manager(s) from the new pool set and
/// atomically swap them into the query path. New servers become usable immediately.
#[async_trait]
pub trait UpstreamReloadPort: Send + Sync {
    /// Rebuilds and applies `pools` to the running resolver(s).
    async fn reload_pools(&self, pools: Vec<UpstreamPool>) -> Result<(), DomainError>;
}
