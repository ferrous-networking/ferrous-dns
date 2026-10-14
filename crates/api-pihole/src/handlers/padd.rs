use axum::extract::{Query, State};
use axum::Json;
use ferrous_dns_domain::{Config, DnssecMode, DomainError};
use serde::Deserialize;

use crate::{
    dto::dns::BlockingStatus,
    dto::padd::{PaddCache, PaddConfig, PaddQueries, PaddResponse, PaddSensors},
    dto::stats::TopDomainsResponse,
    errors::PiholeApiError,
    host, network,
    state::PiholeAppState,
};

use super::{info, stats};

#[derive(Debug, Deserialize)]
pub struct PaddParams {
    /// Adds `iface` and `version`; padd.c defaults it to true.
    full: Option<bool>,
}

/// Pi-hole v6 GET /api/padd
///
/// The figures of `/stats/summary`, the tops, `/dns/blocking`, `/info/system`
/// and `/info/host` in one reply, as PADD polls them. Values Ferrous does not
/// track keep FTL's type with a neutral value (see [`PaddResponse`]).
#[utoipa::path(
    get,
    path = "/padd",
    tag = "pihole:padd",
    params(
        ("full" = Option<bool>, Query, description = "Also report the default interfaces and the version (default true)")
    ),
    responses(
        (status = 200, description = "Summary for the PADD display", body = PaddResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_padd(
    State(state): State<PiholeAppState>,
    Query(params): Query<PaddParams>,
) -> Result<Json<PaddResponse>, PiholeApiError> {
    let full = params.full.unwrap_or(true);
    let period = stats::STATS_PERIOD_HOURS;
    let (summary, top_allowed, top_blocked, top_clients, recent_blocked) = tokio::try_join!(
        stats::summary(&state, period),
        stats::top_domains(&state, period, 1, false),
        stats::top_domains(&state, period, 1, true),
        stats::top_clients(&state, period, 1, false),
        stats::recent_blocked(&state, 1),
    )?;
    let (config, cache) = {
        let config = state.system.config.read().await;
        (padd_config(&config), padd_cache(&state, &config))
    };
    let (system, host, cpu_temp, iface) = tokio::task::spawn_blocking(move || {
        (
            host::read_system(),
            host::read_host(),
            host::read_cpu_temp(),
            full.then(network::read_default_interfaces),
        )
    })
    .await
    .map_err(|e| DomainError::IoError(e.to_string()))?;

    // stats.c get_top_clients: the client's name, or its IP without one.
    let top_client = top_clients
        .clients
        .into_iter()
        .next()
        .map(|(ip, name, _)| name.filter(|name| !name.is_empty()).unwrap_or(ip));
    let first_domain =
        |top: TopDomainsResponse| top.domains.into_iter().next().map(|entry| entry.domain);

    Ok(Json(PaddResponse {
        recent_blocked: recent_blocked.into_iter().next(),
        top_domain: first_domain(top_allowed),
        top_blocked: first_domain(top_blocked),
        top_client,
        active_clients: summary.clients.active,
        gravity_size: summary.gravity.domains_being_blocked,
        blocking: BlockingStatus::from_enabled(
            state.blocking.block_filter_engine.is_blocking_enabled(),
        ),
        queries: PaddQueries {
            total: summary.queries.total,
            blocked: summary.queries.blocked,
            percent_blocked: summary.queries.percent_blocked,
            query_frequency: summary.queries.frequency,
        },
        cache,
        cpu_percent: system.ftl.cpu_percent,
        mem_percent: system.ftl.mem_percent,
        system,
        node_name: host.uname.nodename,
        host_model: host.model,
        iface,
        version: full.then(info::version_components),
        config,
        pid: std::process::id(),
        sensors: PaddSensors {
            cpu_temp,
            hot_limit: host::HOT_LIMIT,
            unit: host::TEMPERATURE_UNIT,
        },
    }))
}

/// FTL's configuration excerpt from the Ferrous settings that mean the same.
fn padd_config(config: &Config) -> PaddConfig {
    let dns = &config.dns;
    // A config without pools forwards to `upstream_servers`.
    let upstreams = if dns.pools.is_empty() {
        dns.upstream_servers.len()
    } else {
        dns.pools.iter().map(|pool| pool.servers.len()).sum()
    };
    PaddConfig {
        dhcp_active: false,
        dhcp_start: String::new(),
        dhcp_end: String::new(),
        dhcp_ipv6: false,
        dns_domain: dns.local_domain.clone().unwrap_or_default(),
        dns_port: config.server.dns_port,
        dns_num_upstreams: upstreams as u64,
        dns_dnssec: dns.effective_dnssec_mode() != DnssecMode::Off,
        // Conditional forwarding is FTL's revServer.
        dns_rev_server_active: matches!(dns.local_dns_server_addr(), Ok(Some(_))),
        privacy_level: 0,
    }
}

/// padd.c: dnsmasq's cache size, insertions and live entries freed.
fn padd_cache(state: &PiholeAppState, config: &Config) -> PaddCache {
    let metrics = state.system.dns_cache.cache_metrics_snapshot();
    PaddCache {
        size: info::cache_capacity(config),
        inserted: metrics.insertions,
        evicted: metrics.evictions,
    }
}
