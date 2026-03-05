use crate::{
    dto::{SettingsDto, UpdateConfigRequest},
    state::AppState,
};
use axum::{extract::State, Json};
use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use tracing::{debug, error, info, instrument};

fn get_writable_config_path() -> Result<String, Json<serde_json::Value>> {
    let path = ferrous_dns_domain::Config::get_config_path().ok_or_else(|| {
        error!("No config file found");
        Json(serde_json::json!({
            "success": false,
            "error": "No config file found. Cannot update configuration."
        }))
    })?;
    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.permissions().readonly() {
            error!("Config file is read-only");
            return Err(Json(serde_json::json!({
                "success": false,
                "error": "Permission denied: Config file is read-only. Please check file permissions."
            })));
        }
    }
    Ok(path)
}

#[instrument(skip(state), name = "api_update_config")]
pub async fn update_config(
    State(state): State<AppState>,
    Json(request): Json<UpdateConfigRequest>,
) -> Json<serde_json::Value> {
    debug!("Updating configuration");

    let config_path = match get_writable_config_path() {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut config = state.config.write().await;

    if let Some(dns_update) = request.dns {
        if let Some(pools) = dns_update.pools {
            config.dns.pools = pools
                .into_iter()
                .map(|p| {
                    let strategy = if p.strategy.eq_ignore_ascii_case("failover") {
                        UpstreamStrategy::Failover
                    } else if p.strategy.eq_ignore_ascii_case("balanced") {
                        UpstreamStrategy::Balanced
                    } else {
                        UpstreamStrategy::Parallel
                    };
                    UpstreamPool {
                        name: p.name,
                        strategy,
                        priority: p.priority,
                        servers: p.servers,
                        weight: None,
                    }
                })
                .collect();
        }
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
        if let Some(interval) = dns_update.cache_compaction_interval {
            config.dns.cache_compaction_interval = interval;
        }
        if let Some(threshold) = dns_update.cache_refresh_threshold {
            config.dns.cache_refresh_threshold = threshold;
        }
        if let Some(refresh) = dns_update.cache_optimistic_refresh {
            config.dns.cache_optimistic_refresh = refresh;
        }
        if let Some(adaptive) = dns_update.cache_adaptive_thresholds {
            config.dns.cache_adaptive_thresholds = adaptive;
        }
        if let Some(window) = dns_update.cache_access_window_secs {
            config.dns.cache_access_window_secs = window;
        }
        if let Some(min_ttl) = dns_update.cache_min_ttl {
            config.dns.cache_min_ttl = min_ttl;
        }
        if let Some(max_ttl) = dns_update.cache_max_ttl {
            config.dns.cache_max_ttl = max_ttl;
        }
        if let Some(block_non_fqdn) = dns_update.block_non_fqdn {
            config.dns.block_non_fqdn = block_non_fqdn;
        }
        if let Some(block_private_ptr) = dns_update.block_private_ptr {
            config.dns.block_private_ptr = block_private_ptr;
        }
        if let Some(local_domain) = dns_update.local_domain {
            config.dns.local_domain = if local_domain.is_empty() {
                None
            } else {
                Some(local_domain)
            };
        }
        if let Some(server) = dns_update.local_dns_server {
            config.dns.local_dns_server = if server.is_empty() {
                None
            } else {
                Some(server)
            };
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

    match state
        .config_file_persistence
        .save_config_to_file(&config, &config_path)
    {
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

#[instrument(skip(state), name = "api_update_settings")]
pub async fn update_settings(
    State(state): State<AppState>,
    Json(request): Json<SettingsDto>,
) -> Json<serde_json::Value> {
    let config_path = match get_writable_config_path() {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut config = state.config.write().await;
    config.dns.block_non_fqdn = request.never_forward_non_fqdn;
    config.dns.block_private_ptr = request.never_forward_reverse_lookups;
    config.dns.local_domain = if request.local_domain.is_empty() {
        None
    } else {
        Some(request.local_domain)
    };
    config.dns.local_dns_server = if request.local_dns_server.is_empty() {
        None
    } else {
        Some(request.local_dns_server)
    };

    match state
        .config_file_persistence
        .save_config_to_file(&config, &config_path)
    {
        Ok(_) => {
            info!("DNS settings updated successfully");
            Json(serde_json::json!({
                "success": true,
                "message": "DNS settings saved successfully."
            }))
        }
        Err(e) => {
            error!(error = %e, "Failed to save DNS settings");
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to save settings: {}", e)
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
            error!("No config file found");
            return Json(serde_json::json!({
                "success": false,
                "error": "No config file found"
            }));
        }
    };

    match ferrous_dns_domain::Config::load(Some(&config_path), Default::default()) {
        Ok(new_config) => {
            let mut config = state.config.write().await;
            *config = new_config;
            info!("Configuration reloaded successfully");
            Json(serde_json::json!({
                "success": true,
                "message": "Configuration reloaded successfully"
            }))
        }
        Err(e) => {
            error!(error = %e, "Failed to reload configuration");
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to reload configuration: {}", e)
            }))
        }
    }
}
