use crate::{
    dto::{
        BlockingConfigResponse, ConfigResponse, DatabaseConfigResponse, DnsConfigResponse,
        LoggingConfigResponse, ServerConfigResponse, UpdateConfigRequest,
    },
    state::AppState,
};
use axum::{extract::State, Json};
use tracing::{debug, error, info, instrument};

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
                enabled: config.dns.health_check.enabled,
                interval_seconds: config.dns.health_check.interval_seconds,
                timeout_ms: config.dns.health_check.timeout_ms,
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
            cache_optimistic_refresh: config.dns.cache_optimistic_refresh,
            cache_adaptive_thresholds: config.dns.cache_adaptive_thresholds,
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

#[instrument(skip(state), name = "api_update_config")]
pub async fn update_config(
    State(state): State<AppState>,
    Json(request): Json<UpdateConfigRequest>,
) -> Json<serde_json::Value> {
    debug!("Updating configuration");

    let config_path = match ferrous_dns_domain::Config::get_config_path() {
        Some(path) => path,
        None => {
            error!("No config file found");
            return Json(serde_json::json!({
                "success": false,
                "error": "No config file found. Cannot update configuration."
            }));
        }
    };

    if let Ok(metadata) = std::fs::metadata(&config_path) {
        if metadata.permissions().readonly() {
            error!("Config file is read-only");
            return Json(serde_json::json!({
                "success": false,
                "error": "Permission denied: Config file is read-only. Please check file permissions."
            }));
        }
    }

    let mut config = state.config.write().await;

    if let Some(dns_update) = request.dns {
        if let Some(upstream) = dns_update.upstream_servers {
            config.dns.upstream_servers = upstream;
        }
        if let Some(cache) = dns_update.cache_enabled {
            config.dns.cache_enabled = cache;
        }
        if let Some(dnssec) = dns_update.dnssec_enabled {
            config.dns.dnssec_enabled = dnssec;
        }
        if let Some(strategy) = dns_update.cache_eviction_strategy {
            config.dns.cache_eviction_strategy = strategy;
        }
        if let Some(max) = dns_update.cache_max_entries {
            config.dns.cache_max_entries = max;
        }
        if let Some(hit_rate) = dns_update.cache_min_hit_rate {
            config.dns.cache_min_hit_rate = hit_rate;
        }
        if let Some(freq) = dns_update.cache_min_frequency {
            config.dns.cache_min_frequency = freq;
        }
        if let Some(score) = dns_update.cache_min_lfuk_score {
            config.dns.cache_min_lfuk_score = score;
        }
        if let Some(refresh) = dns_update.cache_optimistic_refresh {
            config.dns.cache_optimistic_refresh = refresh;
        }
        if let Some(adaptive) = dns_update.cache_adaptive_thresholds {
            config.dns.cache_adaptive_thresholds = adaptive;
        }
    }

    if let Some(blocking_update) = request.blocking {
        if let Some(enabled) = blocking_update.enabled {
            config.blocking.enabled = enabled;
        }
        if let Some(custom) = blocking_update.custom_blocked {
            config.blocking.custom_blocked = custom;
        }
        if let Some(whitelist) = blocking_update.whitelist {
            config.blocking.whitelist = whitelist;
        }
    }

    match config.save(&config_path) {
        Ok(_) => {
            info!("Configuration updated successfully");
            Json(serde_json::json!({
                "success": true,
                "message": "Configuration saved successfully. Use 'Save & Apply Now' button to reload and apply changes immediately, or restart server later.",
                "reload_available": true
            }))
        }
        Err(e) => {
            error!(error = %e, "Failed to save configuration");
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to save configuration: {}", e)
            }))
        }
    }
}

#[instrument(skip(state), name = "api_reload_config")]
pub async fn reload_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    info!("Config reload requested");

    let config_path = match ferrous_dns_domain::Config::get_config_path() {
        Some(path) => path,
        None => {
            error!("No config file found for reload");
            return Json(serde_json::json!({
                "success": false,
                "error": "No config file found. Cannot reload configuration."
            }));
        }
    };

    let new_config = match ferrous_dns_domain::Config::load(Some(&config_path), Default::default())
    {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(error = %e, "Failed to reload config from file");
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to reload config: {}", e)
            }));
        }
    };

    {
        let mut config = state.config.write().await;
        *config = new_config.clone();
        info!("Configuration reloaded from file");
    }

    let entries_before = state.cache.size();
    state.cache.clear();
    let entries_after = state.cache.size();

    info!(
        entries_cleared = entries_before - entries_after,
        "Cache cleared after config reload"
    );

    Json(serde_json::json!({
        "success": true,
        "message": format!(
            "Configuration reloaded successfully. Cache cleared ({} entries removed). Server will use new settings.",
            entries_before
        ),
        "details": {
            "config_path": config_path,
            "cache_entries_cleared": entries_before,
            "dns_cache_enabled": new_config.dns.cache_enabled,
            "optimistic_refresh": new_config.dns.cache_optimistic_refresh,
            "dnssec_enabled": new_config.dns.dnssec_enabled,
            "blocking_enabled": new_config.blocking.enabled
        }
    }))
}
