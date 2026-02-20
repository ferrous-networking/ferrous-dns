use crate::{
    dto::{
        BlockingConfigResponse, ConfigResponse, DatabaseConfigResponse, DnsConfigResponse,
        LoggingConfigResponse, ServerConfigResponse,
    },
    state::AppState,
};
use axum::{extract::State, Json};
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_config")]
pub async fn get_config(State(state): State<AppState>) -> Json<ConfigResponse> {
    debug!("Fetching current configuration");

    let config = state.config.read().await;
    let config_path = ferrous_dns_domain::Config::get_config_path();

    let writable = if let Some(ref path) = config_path {
        std::fs::metadata(path)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    } else {
        false
    };

    Json(ConfigResponse {
        server: ServerConfigResponse {
            dns_port: config.server.dns_port,
            web_port: config.server.web_port,
            bind_address: config.server.bind_address.clone(),
        },
        dns: DnsConfigResponse {
            upstream_servers: config.dns.upstream_servers.clone(),
            pools: config
                .dns
                .pools
                .iter()
                .map(|p| crate::dto::UpstreamPoolResponse {
                    name: p.name.clone(),
                    strategy: format!("{:?}", p.strategy).to_lowercase(),
                    priority: p.priority,
                    servers: p.servers.clone(),
                })
                .collect(),
            health_check: crate::dto::HealthCheckResponse {
                enabled: true,
                interval_seconds: config.dns.health_check.interval,
                timeout_ms: config.dns.health_check.timeout,
                failure_threshold: config.dns.health_check.failure_threshold,
                success_threshold: config.dns.health_check.success_threshold,
            },
            query_timeout: config.dns.query_timeout,
            cache_enabled: config.dns.cache_enabled,
            cache_ttl: config.dns.cache_ttl,
            dnssec_enabled: config.dns.dnssec_enabled,
            cache_eviction_strategy: config.dns.cache_eviction_strategy.clone(),
            cache_max_entries: config.dns.cache_max_entries,
            cache_min_hit_rate: config.dns.cache_min_hit_rate,
            cache_min_frequency: config.dns.cache_min_frequency,
            cache_min_lfuk_score: config.dns.cache_min_lfuk_score,
            cache_compaction_interval: config.dns.cache_compaction_interval,
            cache_refresh_threshold: config.dns.cache_refresh_threshold,
            cache_optimistic_refresh: config.dns.cache_optimistic_refresh,
            cache_adaptive_thresholds: config.dns.cache_adaptive_thresholds,
            cache_access_window_secs: config.dns.cache_access_window_secs,
            block_non_fqdn: config.dns.block_non_fqdn,
            block_private_ptr: config.dns.block_private_ptr,
            local_domain: config.dns.local_domain.clone(),
            conditional_forwarding: config
                .dns
                .conditional_forwarding
                .iter()
                .map(|cf| crate::dto::ConditionalForwardingResponse {
                    domain: cf.domain.clone(),
                    server: cf.server.clone(),
                })
                .collect(),
        },
        blocking: BlockingConfigResponse {
            enabled: config.blocking.enabled,
            custom_blocked: config.blocking.custom_blocked.clone(),
            whitelist: config.blocking.whitelist.clone(),
        },
        logging: LoggingConfigResponse {
            level: config.logging.level.clone(),
        },
        database: DatabaseConfigResponse {
            path: config.database.path.clone(),
            log_queries: config.database.log_queries,
        },
        config_path,
        writable,
    })
}

#[instrument(skip(state), name = "api_get_settings")]
pub async fn get_settings(State(state): State<AppState>) -> Json<crate::dto::SettingsDto> {
    debug!("Fetching settings");
    let response = get_config(State(state)).await;
    Json(response.0.into())
}
