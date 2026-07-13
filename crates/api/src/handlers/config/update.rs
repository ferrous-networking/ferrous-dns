use crate::{
    dto::{SettingsDto, UpdateConfigRequest},
    state::AppState,
};
use axum::{extract::State, Json};
use ferrous_dns_domain::{DnsProtocol, UpstreamPool, UpstreamStrategy};
use tracing::{debug, error, info, instrument};

async fn get_writable_config_path(
    state: &crate::state::AppState,
) -> Result<String, Json<serde_json::Value>> {
    let path = state.resolve_config_path().ok_or_else(|| {
        error!("No config file found");
        Json(serde_json::json!({
            "success": false,
            "error": "No config file found. Cannot update configuration."
        }))
    })?;
    if let Ok(metadata) = tokio::fs::metadata(&path).await {
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

#[utoipa::path(
    post,
    path = "/config",
    tag = "config",
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Configuration updated"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_update_config")]
pub async fn update_config(
    State(state): State<AppState>,
    Json(request): Json<UpdateConfigRequest>,
) -> Json<serde_json::Value> {
    debug!("Updating configuration");

    let config_path = match get_writable_config_path(&state).await {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut new_config = state.config.read().await.clone();
    // Snapshot to detect which (non-pool) fields actually changed, so we only
    // ask for a restart when something that is NOT hot-applied was modified.
    let original_config = new_config.clone();
    // Upstream pools are the only key applied live (no restart). Tracks whether
    // the request carried a pool update so we can hot-reload after saving.
    let mut pools_provided = false;

    if let Some(server_update) = request.server {
        if let Some(pihole_compat) = server_update.pihole_compat {
            new_config.server.pihole_compat = pihole_compat;
        }
        if let Some(web_tls_update) = server_update.web_tls {
            if let Some(enabled) = web_tls_update.enabled {
                new_config.server.web_tls.enabled = enabled;
            }
            if let Some(cert) = web_tls_update.tls_cert_path {
                new_config.server.web_tls.tls_cert_path = cert;
            }
            if let Some(key) = web_tls_update.tls_key_path {
                new_config.server.web_tls.tls_key_path = key;
            }
        }
    }

    if let Some(dns_update) = request.dns {
        if let Some(pools) = dns_update.pools {
            pools_provided = true;
            let mut validated: Vec<UpstreamPool> = Vec::new();
            for p in pools {
                let strategy = if p.strategy.eq_ignore_ascii_case("failover") {
                    UpstreamStrategy::Failover
                } else if p.strategy.eq_ignore_ascii_case("balanced") {
                    UpstreamStrategy::Balanced
                } else {
                    UpstreamStrategy::Parallel
                };
                // Strip blank entries and reject anything that is not a valid
                // upstream endpoint — an invalid string here would break the
                // server on its next boot (PoolManager parses every server).
                let mut servers: Vec<String> = Vec::new();
                for s in p.servers {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Err(e) = trimmed.parse::<DnsProtocol>() {
                        return Json(serde_json::json!({
                            "success": false,
                            "error": format!(
                                "Invalid server '{}' in pool '{}': {}",
                                trimmed, p.name, e
                            )
                        }));
                    }
                    servers.push(trimmed.to_string());
                }
                // Drop pools left without any server.
                if servers.is_empty() {
                    continue;
                }
                validated.push(UpstreamPool {
                    name: p.name,
                    strategy,
                    priority: p.priority,
                    servers,
                    weight: p.weight,
                });
            }
            if validated.is_empty() {
                return Json(serde_json::json!({
                    "success": false,
                    "error": "At least one pool with a valid server is required"
                }));
            }
            new_config.dns.pools = validated;
        }
        if let Some(upstream) = dns_update.upstream_servers {
            new_config.dns.upstream_servers = upstream;
        }
        if let Some(cache) = dns_update.cache_enabled {
            new_config.dns.cache_enabled = cache;
        }
        if let Some(mode_str) = dns_update.dnssec_mode {
            match crate::dto::config::parse_dnssec_mode(&mode_str) {
                Ok(mode) => new_config.dns.dnssec_mode = Some(mode),
                Err(e) => return Json(serde_json::json!({ "success": false, "error": e })),
            }
        } else if let Some(dnssec) = dns_update.dnssec_enabled {
            // Deprecated compat: map the old boolean onto the mode (source of truth).
            new_config.dns.dnssec_mode = Some(if dnssec {
                ferrous_dns_domain::DnssecMode::Permissive
            } else {
                ferrous_dns_domain::DnssecMode::Off
            });
        }
        if let Some(strategy) = dns_update.cache_eviction_strategy {
            new_config.dns.cache_eviction_strategy = strategy;
        }
        if let Some(max) = dns_update.cache_max_entries {
            new_config.dns.cache_max_entries = max;
        }
        if let Some(hit_rate) = dns_update.cache_min_hit_rate {
            new_config.dns.cache_min_hit_rate = hit_rate;
        }
        if let Some(freq) = dns_update.cache_min_frequency {
            new_config.dns.cache_min_frequency = freq;
        }
        if let Some(score) = dns_update.cache_min_lfuk_score {
            new_config.dns.cache_min_lfuk_score = score;
        }
        if let Some(interval) = dns_update.cache_compaction_interval {
            new_config.dns.cache_compaction_interval = interval;
        }
        if let Some(threshold) = dns_update.cache_refresh_threshold {
            new_config.dns.cache_refresh_threshold = threshold;
        }
        if let Some(refresh) = dns_update.cache_optimistic_refresh {
            new_config.dns.cache_optimistic_refresh = refresh;
        }
        if let Some(adaptive) = dns_update.cache_adaptive_thresholds {
            new_config.dns.cache_adaptive_thresholds = adaptive;
        }
        if let Some(window) = dns_update.cache_access_window_secs {
            new_config.dns.cache_access_window_secs = window;
        }
        if let Some(min_ttl) = dns_update.cache_min_ttl {
            new_config.dns.cache_min_ttl = min_ttl;
        }
        if let Some(max_ttl) = dns_update.cache_max_ttl {
            new_config.dns.cache_max_ttl = max_ttl;
        }
        if let Some(block_non_fqdn) = dns_update.block_non_fqdn {
            new_config.dns.block_non_fqdn = block_non_fqdn;
        }
        if let Some(block_private_ptr) = dns_update.block_private_ptr {
            new_config.dns.block_private_ptr = block_private_ptr;
        }
        if let Some(local_domain) = dns_update.local_domain {
            new_config.dns.local_domain = if local_domain.is_empty() {
                None
            } else {
                Some(local_domain)
            };
        }
        if let Some(server) = dns_update.local_dns_server {
            new_config.dns.local_dns_server = if server.is_empty() {
                None
            } else {
                Some(server)
            };
        }
        if let Some(v) = dns_update.mdns_enabled {
            new_config.dns.mdns_enabled = v;
        }
        if let Some(rl) = dns_update.rate_limit {
            if let Some(v) = rl.enabled {
                new_config.dns.rate_limit.enabled = v;
            }
            if let Some(v) = rl.queries_per_second {
                new_config.dns.rate_limit.queries_per_second = v;
            }
            if let Some(v) = rl.burst_size {
                new_config.dns.rate_limit.burst_size = v;
            }
            if let Some(v) = rl.ipv4_prefix_len {
                new_config.dns.rate_limit.ipv4_prefix_len = v;
            }
            if let Some(v) = rl.ipv6_prefix_len {
                new_config.dns.rate_limit.ipv6_prefix_len = v;
            }
            if let Some(v) = rl.nxdomain_per_second {
                new_config.dns.rate_limit.nxdomain_per_second = v;
            }
            if let Some(v) = rl.slip_ratio {
                new_config.dns.rate_limit.slip_ratio = v;
            }
            if let Some(v) = rl.dry_run {
                new_config.dns.rate_limit.dry_run = v;
            }
            if let Some(v) = rl.stale_entry_ttl_secs {
                new_config.dns.rate_limit.stale_entry_ttl_secs = v;
            }
            if let Some(v) = rl.tcp_max_connections_per_ip {
                new_config.dns.rate_limit.tcp_max_connections_per_ip = v;
            }
            if let Some(v) = rl.dot_max_connections_per_ip {
                new_config.dns.rate_limit.dot_max_connections_per_ip = v;
            }
            if let Some(v) = rl.doq_max_connections_per_ip {
                new_config.dns.rate_limit.doq_max_connections_per_ip = v;
            }
            if let Some(v) = rl.whitelist {
                new_config.dns.rate_limit.whitelist = v;
            }
        }
    }

    if let Some(blocking_update) = request.blocking {
        if let Some(enabled) = blocking_update.enabled {
            new_config.blocking.enabled = enabled;
        }
        if let Some(custom) = blocking_update.custom_blocked {
            new_config.blocking.custom_blocked = custom;
        }
        if let Some(whitelist) = blocking_update.whitelist {
            new_config.blocking.whitelist = whitelist;
        }
        if let Some(block_mode) = blocking_update.block_mode {
            new_config.blocking.block_mode = crate::dto::config::block_mode_from_str(&block_mode);
        }
        if let Some(block_ttl) = blocking_update.block_ttl {
            new_config.blocking.block_ttl = block_ttl;
        }
        if let Some(sinkhole_ipv4) = blocking_update.sinkhole_ipv4 {
            match crate::dto::config::parse_sinkhole_ipv4(&sinkhole_ipv4) {
                Ok(addr) => new_config.blocking.sinkhole_ipv4 = addr,
                Err(e) => return Json(serde_json::json!({ "success": false, "error": e })),
            }
        }
        if let Some(sinkhole_ipv6) = blocking_update.sinkhole_ipv6 {
            match crate::dto::config::parse_sinkhole_ipv6(&sinkhole_ipv6) {
                Ok(addr) => new_config.blocking.sinkhole_ipv6 = addr,
                Err(e) => return Json(serde_json::json!({ "success": false, "error": e })),
            }
        }
    }

    if let Some(auth_update) = request.auth {
        if let Some(enabled) = auth_update.enabled {
            new_config.auth.enabled = enabled;
        }
        if let Some(ttl) = auth_update.session_ttl_hours {
            new_config.auth.session_ttl_hours = ttl;
        }
        if let Some(days) = auth_update.remember_me_days {
            new_config.auth.remember_me_days = days;
        }
        if let Some(attempts) = auth_update.login_rate_limit_attempts {
            new_config.auth.login_rate_limit_attempts = attempts;
        }
        if let Some(window) = auth_update.login_rate_limit_window_secs {
            new_config.auth.login_rate_limit_window_secs = window;
        }
    }

    // Upstream pools are hot-applied; every other field requires a restart.
    // Detect a non-pool change by diffing the config with pools blanked out.
    let restart_required = {
        let mut before = original_config.clone();
        let mut after = new_config.clone();
        before.dns.pools.clear();
        after.dns.pools.clear();
        serde_json::to_value(&before).ok() != serde_json::to_value(&after).ok()
    };

    let new_pools = new_config.dns.pools.clone();

    // Hot-apply upstream pool changes to the running resolver(s) BEFORE persisting.
    // reload_pools stages a rebuild for every manager and only swaps once all of
    // them succeed, so a rebuild failure here leaves the live resolver untouched —
    // and since nothing has been written yet, the saved config can never diverge
    // from what the resolver actually serves.
    if pools_provided {
        if let Err(e) = state.dns.reload_upstream.reload_pools(new_pools).await {
            error!(error = %e, "Failed to hot-reload upstream pools; configuration not saved");
            return Json(serde_json::json!({
                "success": false,
                "error": format!(
                    "Failed to apply upstream pools live; configuration not saved: {}",
                    e
                )
            }));
        }
        info!("Upstream pools applied live");
    }

    match state
        .config_file_persistence
        .save_config_to_file(&new_config, &config_path)
    {
        Ok(_) => {
            *state.config.write().await = new_config;
            info!("Configuration updated successfully");

            let message = if restart_required {
                "Configuration saved. Restart the server for the changes to take effect."
            } else if pools_provided {
                "Upstream pools saved and applied immediately. No restart needed."
            } else {
                "Configuration saved successfully."
            };
            Json(serde_json::json!({
                "success": true,
                "message": message,
                "reload_available": true,
                "restart_required": restart_required
            }))
        }
        Err(e) => {
            error!(error = %e, "Failed to save configuration");
            // Pools were already hot-applied to the live resolver above, so on a
            // save failure the running server and the on-disk config diverge: the
            // resolver serves the new pools but a restart would revert to the old
            // ones. Tell the user so they can retry the save rather than assume the
            // change didn't take effect.
            let error = if pools_provided {
                format!(
                    "Upstream pools were applied to the running server but the configuration file could not be saved, so a restart would revert them. Retry the save. ({})",
                    e
                )
            } else {
                format!("Failed to save configuration: {}", e)
            };
            Json(serde_json::json!({
                "success": false,
                "error": error
            }))
        }
    }
}

#[utoipa::path(
    post,
    path = "/settings",
    tag = "config",
    request_body = SettingsDto,
    responses(
        (status = 200, description = "Settings updated"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_update_settings")]
pub async fn update_settings(
    State(state): State<AppState>,
    Json(request): Json<SettingsDto>,
) -> Json<serde_json::Value> {
    let config_path = match get_writable_config_path(&state).await {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut new_config = state.config.read().await.clone();
    new_config.dns.block_non_fqdn = request.never_forward_non_fqdn;
    new_config.dns.block_private_ptr = request.never_forward_reverse_lookups;
    new_config.dns.local_domain = if request.local_domain.is_empty() {
        None
    } else {
        Some(request.local_domain)
    };
    new_config.dns.local_dns_server = if request.local_dns_server.is_empty() {
        None
    } else {
        Some(request.local_dns_server)
    };
    new_config.blocking.block_mode = crate::dto::config::block_mode_from_str(&request.block_mode);
    new_config.blocking.block_ttl = request.block_ttl;
    new_config.blocking.sinkhole_ipv4 =
        match crate::dto::config::parse_sinkhole_ipv4(&request.sinkhole_ipv4) {
            Ok(addr) => addr,
            Err(e) => return Json(serde_json::json!({ "success": false, "error": e })),
        };
    new_config.blocking.sinkhole_ipv6 =
        match crate::dto::config::parse_sinkhole_ipv6(&request.sinkhole_ipv6) {
            Ok(addr) => addr,
            Err(e) => return Json(serde_json::json!({ "success": false, "error": e })),
        };
    new_config.dns64.enabled = request.dns64_enabled;
    if !request.nat64_prefix.trim().is_empty() {
        new_config.dns64.prefix =
            match crate::dto::config::parse_dns64_prefix(&request.nat64_prefix) {
                Ok(prefix) => prefix,
                Err(e) => return Json(serde_json::json!({ "success": false, "error": e })),
            };
    }

    match state
        .config_file_persistence
        .save_config_to_file(&new_config, &config_path)
    {
        Ok(_) => {
            *state.config.write().await = new_config;
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

#[utoipa::path(
    post,
    path = "/config/reload",
    tag = "config",
    responses(
        (status = 200, description = "Configuration reloaded"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_reload_config")]
pub async fn reload_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    info!("Config reload requested");

    let config_path = match state.resolve_config_path() {
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
