use super::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::UpstreamReloadPort;
use ferrous_dns_domain::{DomainError, UpstreamPool};
use std::sync::Arc;

/// Applies upstream pool changes to the live resolver(s) without a restart.
///
/// Holds every pool manager that forwards to upstreams — the main resolver, the
/// separate DNSSEC resolver, and the cache optimistic-refresh resolver — so all
/// of them are kept in sync when pools change.
pub struct UpstreamReloadAdapter {
    pool_managers: Vec<Arc<PoolManager>>,
}

impl UpstreamReloadAdapter {
    pub fn new(pool_managers: Vec<Arc<PoolManager>>) -> Self {
        Self { pool_managers }
    }
}

#[async_trait]
impl UpstreamReloadPort for UpstreamReloadAdapter {
    async fn reload_pools(&self, pools: Vec<UpstreamPool>) -> Result<(), DomainError> {
        // Stage every rebuild before swapping any of them, so a failure on a later
        // manager can't leave the set serving different upstreams. If any prepare
        // fails, no live pool set is touched. The rebuilds are independent and each
        // resolves the same upstream hostnames, so run them concurrently instead of
        // serially — otherwise a slow hostname stacks one timeout per manager.
        let prepared = futures::future::try_join_all(
            self.pool_managers
                .iter()
                .map(|pm| pm.prepare(pools.clone())),
        )
        .await?;
        for (pm, p) in self.pool_managers.iter().zip(prepared) {
            pm.apply(p);
        }
        Ok(())
    }
}
