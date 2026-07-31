use anyhow::Context;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::dnssec::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::{HickoryDnsResolver, PoolManager};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::wiring::Repositories;

pub(super) fn build_resolver(
    pool_manager: Arc<PoolManager>,
    pool_manager_for_dnssec: Arc<PoolManager>,
    config: &Config,
    repos: &Repositories,
    timeout_ms: u64,
) -> anyhow::Result<HickoryDnsResolver> {
    let dnssec_mode = config.dns.effective_dnssec_mode();
    let dnssec_validates = dnssec_mode.validates();

    let mut resolver = HickoryDnsResolver::new_with_pools(
        pool_manager,
        timeout_ms,
        dnssec_validates,
        Some(repos.query_log.clone()),
    )?
    .with_query_filters(
        config.dns.block_private_ptr,
        config.dns.block_non_fqdn,
        config.dns.local_domain.clone(),
        config.dns.local_dns_server.is_some(),
    )
    .with_local_dns_server(config.dns.local_dns_server.clone());

    if dnssec_validates {
        resolver = resolver
            .with_dnssec_pool_manager(pool_manager_for_dnssec)
            .with_trust_anchors(load_trust_anchors(config)?);
    } else if config.dns.dnssec_trust_anchor_file.is_some() {
        debug!("DNSSEC validation is off — dnssec_trust_anchor_file is ignored");
    }

    // DNS64 (RFC 6147) — fail-soft: a malformed / non-/96 prefix disables the
    // feature with a warning rather than refusing to start.
    if config.dns64.enabled {
        match config.dns64.parsed_prefix() {
            Some(prefix) => {
                resolver = resolver.with_dns64(prefix);
                info!(prefix = %prefix, "DNS64 AAAA synthesis enabled");
            }
            None => warn!(
                prefix = %config.dns64.prefix,
                "DNS64 enabled but prefix is invalid (only /96 is supported) — DNS64 disabled"
            ),
        }
    }

    info!(
        dnssec_mode = %dnssec_mode,
        pools = config.dns.pools.len(),
        block_private_ptr = config.dns.block_private_ptr,
        block_non_fqdn = config.dns.block_non_fqdn,
        local_domain = ?config.dns.local_domain,
        local_dns_server = ?config.dns.local_dns_server,
        "DNS resolver created with all features"
    );

    Ok(resolver)
}

/// Loads the DNSSEC trust anchors: the operator's file when one is configured,
/// the IANA root anchors embedded in the binary otherwise.
///
/// A configured file that cannot be read or parsed aborts startup instead of
/// falling back to the embedded set — silently keeping the old trust root would
/// leave the operator believing they had replaced it.
fn load_trust_anchors(config: &Config) -> anyhow::Result<TrustAnchorStore> {
    let configured_path = config.dns.dnssec_trust_anchor_file.as_deref();

    let store = match configured_path {
        Some(path) => TrustAnchorStore::from_file(path)
            .with_context(|| format!("failed to load DNSSEC trust anchors from {path}"))?,
        None => TrustAnchorStore::new(),
    };

    info!(
        count = store.len(),
        source = configured_path.unwrap_or("embedded"),
        "DNSSEC trust anchors loaded"
    );

    for anchor in store.iter() {
        debug!(
            zone = %anchor.domain,
            key_tag = anchor.key_tag(),
            algorithm = anchor.algorithm(),
            description = %anchor.description,
            "DNSSEC trust anchor"
        );
    }

    Ok(store)
}
