use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{HickoryDnsResolver, PoolManager};
use std::sync::Arc;
use tracing::info;

use crate::wiring::Repositories;

pub(super) fn build_resolver(
    pool_manager: Arc<PoolManager>,
    pool_manager_for_dnssec: Arc<PoolManager>,
    config: &Config,
    repos: &Repositories,
    timeout_ms: u64,
) -> anyhow::Result<HickoryDnsResolver> {
    let mut resolver = HickoryDnsResolver::new_with_pools(
        pool_manager,
        timeout_ms,
        config.dns.dnssec_enabled,
        Some(repos.query_log.clone()),
    )?
    .with_query_filters(
        config.dns.block_private_ptr,
        config.dns.block_non_fqdn,
        config.dns.local_domain.clone(),
        config.dns.local_dns_server.is_some(),
    )
    .with_local_dns_server(config.dns.local_dns_server.clone());

    if config.dns.dnssec_enabled {
        resolver = resolver.with_dnssec_pool_manager(pool_manager_for_dnssec);
    }

    info!(
        dnssec_enabled = config.dns.dnssec_enabled,
        pools = config.dns.pools.len(),
        block_private_ptr = config.dns.block_private_ptr,
        block_non_fqdn = config.dns.block_non_fqdn,
        local_domain = ?config.dns.local_domain,
        local_dns_server = ?config.dns.local_dns_server,
        "DNS resolver created with all features"
    );

    Ok(resolver)
}
