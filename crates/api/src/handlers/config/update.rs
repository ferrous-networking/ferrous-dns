use crate::{
    dto::{
        config::{
            parse_dns64_prefix, parse_sinkhole_ipv4, parse_sinkhole_ipv6, ConfigSaveResponse,
            PoolUpdate,
        },
        SettingsDto, UpdateConfigRequest,
    },
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use ferrous_dns_domain::{
    Config, DnsConfig, DnsProtocol, DnssecMode, DomainError, UpstreamPool, UpstreamStrategy,
};
use tokio::sync::OwnedMutexGuard;
use tracing::{debug, error, info, instrument, Instrument};

type SaveResponse = (StatusCode, Json<ConfigSaveResponse>);

/// The request itself is invalid.
fn rejected(error: impl Into<String>) -> SaveResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(ConfigSaveResponse::failure(error)),
    )
}

/// The request was valid but could not be carried out.
fn not_saved(error: impl Into<String>) -> SaveResponse {
    (StatusCode::OK, Json(ConfigSaveResponse::failure(error)))
}

fn pools_applied_but_not_saved(error: impl std::fmt::Display) -> String {
    format!(
        "Upstream pools were applied to the running server but the configuration file could not be saved, so a restart would revert them. Retry the save. ({error})"
    )
}

fn config_differs(before: &Config, after: &Config) -> bool {
    serde_json::to_value(before).ok() != serde_json::to_value(after).ok()
}

fn non_empty(value: String) -> Option<String> {
    Some(value).filter(|v| !v.is_empty())
}

/// Saved as `IP:port`, so a bare router IP is stored with its implied port 53.
fn local_dns_server(value: String) -> Result<Option<String>, String> {
    non_empty(value)
        .map(|v| DnsConfig::parse_local_dns_server(&v).map(|addr| addr.to_string()))
        .transpose()
        .map_err(|e| e.to_string())
}

async fn get_writable_config_path(state: &AppState) -> Result<String, SaveResponse> {
    let path = state.config_path.as_deref().ok_or_else(|| {
        error!("No config file found");
        not_saved("No config file found. Cannot update configuration.")
    })?;
    if let Ok(metadata) = tokio::fs::metadata(path).await {
        if metadata.permissions().readonly() {
            error!("Config file is read-only");
            return Err(not_saved(
                "Permission denied: Config file is read-only. Please check file permissions.",
            ));
        }
    }
    Ok(path.to_string())
}

/// Drops blank servers and serverless pools; rejects any server string the
/// resolver could not parse on its next boot.
fn parse_pools(pools: Vec<PoolUpdate>) -> Result<Vec<UpstreamPool>, String> {
    let mut validated = Vec::with_capacity(pools.len());
    for p in pools {
        let strategy = if p.strategy.eq_ignore_ascii_case("failover") {
            UpstreamStrategy::Failover
        } else if p.strategy.eq_ignore_ascii_case("balanced") {
            UpstreamStrategy::Balanced
        } else {
            UpstreamStrategy::Parallel
        };
        let mut servers = Vec::with_capacity(p.servers.len());
        for s in p.servers {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Err(e) = trimmed.parse::<DnsProtocol>() {
                // The parser's message already names the server; skip the
                // "Configuration error:" prefix so the UI shows only the hint.
                let reason = match e {
                    DomainError::ConfigError(reason) => reason,
                    other => other.to_string(),
                };
                return Err(format!("Pool '{}': {reason}", p.name));
            }
            servers.push(trimmed.to_string());
        }
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
        return Err("At least one pool with a valid server is required".to_string());
    }
    Ok(validated)
}

/// Merges `request` into a copy of `current` and validates the result; also
/// returns whether the upstream pools were replaced.
fn merge_config_update(
    current: &Config,
    request: UpdateConfigRequest,
) -> Result<(Config, bool), String> {
    let mut merged = current.clone();
    let pools_provided = apply_config_update(&mut merged, request)?;
    merged.validate().map_err(|e| e.to_string())?;
    Ok((merged, pools_provided))
}

/// Merges `request` into `cfg`; returns whether the upstream pools were replaced.
fn apply_config_update(cfg: &mut Config, request: UpdateConfigRequest) -> Result<bool, String> {
    let mut pools_provided = false;

    if let Some(server) = request.server {
        if let Some(v) = server.pihole_compat {
            cfg.server.pihole_compat = v;
        }
        if let Some(web_tls) = server.web_tls {
            if let Some(v) = web_tls.enabled {
                cfg.server.web_tls.enabled = v;
            }
            if let Some(v) = web_tls.tls_cert_path {
                cfg.server.web_tls.tls_cert_path = v;
            }
            if let Some(v) = web_tls.tls_key_path {
                cfg.server.web_tls.tls_key_path = v;
            }
        }
    }

    if let Some(dns) = request.dns {
        if let Some(pools) = dns.pools {
            cfg.dns.pools = parse_pools(pools)?;
            pools_provided = true;
        }
        if let Some(v) = dns.upstream_servers {
            cfg.dns.upstream_servers = v;
        }
        if let Some(v) = dns.cache_enabled {
            cfg.dns.cache_enabled = v;
        }
        if let Some(mode) = dns.dnssec_mode {
            cfg.dns.dnssec_mode = Some(mode.parse::<DnssecMode>()?);
        } else if let Some(enabled) = dns.dnssec_enabled {
            cfg.dns.dnssec_mode = Some(if enabled {
                DnssecMode::Permissive
            } else {
                DnssecMode::Off
            });
        }
        if let Some(v) = dns.cache_eviction_strategy {
            cfg.dns.cache_eviction_strategy = v
                .parse::<ferrous_dns_domain::config::CacheEvictionStrategy>()
                .map_err(|e| e.to_string())?;
        }
        if let Some(v) = dns.cache_max_entries {
            cfg.dns.cache_max_entries = v;
        }
        if let Some(v) = dns.cache_min_hit_rate {
            cfg.dns.cache_min_hit_rate = v;
        }
        if let Some(v) = dns.cache_min_frequency {
            cfg.dns.cache_min_frequency = v;
        }
        if let Some(v) = dns.cache_min_lfuk_score {
            cfg.dns.cache_min_lfuk_score = v;
        }
        if let Some(v) = dns.cache_compaction_interval {
            cfg.dns.cache_compaction_interval = v;
        }
        if let Some(v) = dns.cache_refresh_threshold {
            cfg.dns.cache_refresh_threshold = v;
        }
        if let Some(v) = dns.cache_optimistic_refresh {
            cfg.dns.cache_optimistic_refresh = v;
        }
        if let Some(v) = dns.cache_adaptive_thresholds {
            cfg.dns.cache_adaptive_thresholds = v;
        }
        if let Some(v) = dns.cache_access_window_secs {
            cfg.dns.cache_access_window_secs = v;
        }
        if let Some(v) = dns.cache_min_ttl {
            cfg.dns.cache_min_ttl = v;
        }
        if let Some(v) = dns.cache_max_ttl {
            cfg.dns.cache_max_ttl = v;
        }
        if let Some(v) = dns.block_non_fqdn {
            cfg.dns.block_non_fqdn = v;
        }
        if let Some(v) = dns.block_private_ptr {
            cfg.dns.block_private_ptr = v;
        }
        if let Some(v) = dns.local_domain {
            cfg.dns.local_domain = non_empty(v);
        }
        if let Some(v) = dns.local_dns_server {
            cfg.dns.local_dns_server = local_dns_server(v)?;
        }
        if let Some(v) = dns.mdns_enabled {
            cfg.dns.mdns_enabled = v;
        }
        if let Some(rl) = dns.rate_limit {
            let target = &mut cfg.dns.rate_limit;
            if let Some(v) = rl.enabled {
                target.enabled = v;
            }
            if let Some(v) = rl.queries_per_second {
                target.queries_per_second = v;
            }
            if let Some(v) = rl.burst_size {
                target.burst_size = v;
            }
            if let Some(v) = rl.ipv4_prefix_len {
                target.ipv4_prefix_len = v;
            }
            if let Some(v) = rl.ipv6_prefix_len {
                target.ipv6_prefix_len = v;
            }
            if let Some(v) = rl.nxdomain_per_second {
                target.nxdomain_per_second = v;
            }
            if let Some(v) = rl.slip_ratio {
                target.slip_ratio = v;
            }
            if let Some(v) = rl.dry_run {
                target.dry_run = v;
            }
            if let Some(v) = rl.stale_entry_ttl_secs {
                target.stale_entry_ttl_secs = v;
            }
            if let Some(v) = rl.tcp_max_connections_per_ip {
                target.tcp_max_connections_per_ip = v;
            }
            if let Some(v) = rl.dot_max_connections_per_ip {
                target.dot_max_connections_per_ip = v;
            }
            if let Some(v) = rl.doq_max_connections_per_ip {
                target.doq_max_connections_per_ip = v;
            }
            if let Some(v) = rl.whitelist {
                target.whitelist = v;
            }
        }
    }

    if let Some(blocking) = request.blocking {
        if let Some(v) = blocking.enabled {
            cfg.blocking.enabled = v;
        }
        if let Some(v) = blocking.custom_blocked {
            cfg.blocking.custom_blocked = v;
        }
        if let Some(v) = blocking.whitelist {
            cfg.blocking.whitelist = v;
        }
        if let Some(v) = blocking.block_mode {
            cfg.blocking.block_mode = v.parse()?;
        }
        if let Some(v) = blocking.block_ttl {
            cfg.blocking.block_ttl = v;
        }
        if let Some(v) = blocking.sinkhole_ipv4 {
            cfg.blocking.sinkhole_ipv4 = parse_sinkhole_ipv4(&v)?;
        }
        if let Some(v) = blocking.sinkhole_ipv6 {
            cfg.blocking.sinkhole_ipv6 = parse_sinkhole_ipv6(&v)?;
        }
    }

    if let Some(auth) = request.auth {
        if let Some(v) = auth.enabled {
            cfg.auth.enabled = v;
        }
        if let Some(v) = auth.session_ttl_hours {
            cfg.auth.session_ttl_hours = v;
        }
        if let Some(v) = auth.remember_me_days {
            cfg.auth.remember_me_days = v;
        }
        if let Some(v) = auth.login_rate_limit_attempts {
            cfg.auth.login_rate_limit_attempts = v;
        }
        if let Some(v) = auth.login_rate_limit_window_secs {
            cfg.auth.login_rate_limit_window_secs = v;
        }
    }

    Ok(pools_provided)
}

fn apply_settings(cfg: &mut Config, request: SettingsDto) -> Result<(), String> {
    cfg.dns.block_non_fqdn = request.never_forward_non_fqdn;
    cfg.dns.block_private_ptr = request.never_forward_reverse_lookups;
    cfg.dns.local_domain = non_empty(request.local_domain);
    cfg.dns.local_dns_server = local_dns_server(request.local_dns_server)?;
    cfg.blocking.block_mode = request.block_mode.parse()?;
    cfg.blocking.block_ttl = request.block_ttl;
    cfg.blocking.sinkhole_ipv4 = parse_sinkhole_ipv4(&request.sinkhole_ipv4)?;
    cfg.blocking.sinkhole_ipv6 = parse_sinkhole_ipv6(&request.sinkhole_ipv6)?;
    cfg.dns64.enabled = request.dns64_enabled;
    if !request.nat64_prefix.trim().is_empty() {
        cfg.dns64.prefix = parse_dns64_prefix(&request.nat64_prefix)?;
    }
    cfg.validate().map_err(|e| e.to_string())
}

#[utoipa::path(
    post,
    path = "/config",
    tag = "config",
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Save outcome; `success` is false when the update could not be saved", body = ConfigSaveResponse),
        (status = 400, description = "The update carries an invalid value; nothing was applied", body = ConfigSaveResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_update_config")]
pub async fn update_config(
    State(state): State<AppState>,
    Json(request): Json<UpdateConfigRequest>,
) -> SaveResponse {
    debug!("Updating configuration");

    let config_path = match get_writable_config_path(&state).await {
        Ok(p) => p,
        Err(e) => return e,
    };

    let writer = state.config_writer.clone().lock_owned().await;
    // Pools go live before the save, so a dropped request must not abandon it half-way.
    tokio::spawn(save_config_update(state, request, config_path, writer).in_current_span())
        .await
        .unwrap_or_else(|e| {
            error!(error = %e, "Configuration save task failed");
            not_saved(format!("Configuration save failed: {e}"))
        })
}

async fn save_config_update(
    state: AppState,
    request: UpdateConfigRequest,
    config_path: String,
    _writer: OwnedMutexGuard<()>,
) -> SaveResponse {
    // Checked before anything is applied, so a rejected request never reaches the live pools.
    let (candidate, pools_provided) =
        match merge_config_update(&*state.config.read().await, request.clone()) {
            Ok(merged) => merged,
            Err(e) => return rejected(e),
        };

    // No config lock is held here: resolving upstream hostnames can take seconds.
    // reload_pools swaps only once every manager rebuilt, so a failure leaves
    // both the resolver and the file untouched.
    if pools_provided {
        if let Err(e) = state
            .dns
            .reload_upstream
            .reload_pools(candidate.dns.pools)
            .await
        {
            error!(error = %e, "Failed to hot-reload upstream pools; configuration not saved");
            return not_saved(format!(
                "Failed to apply upstream pools live; configuration not saved: {e}"
            ));
        }
        info!("Upstream pools applied live");
    }

    // Local-record and password writers don't take `config_writer`, so the
    // request is merged again into whatever they stored meanwhile.
    let mut config = state.config.write().await;
    let new_config = match merge_config_update(&config, request) {
        Ok((merged, _)) => merged,
        Err(e) if pools_provided => return not_saved(pools_applied_but_not_saved(e)),
        Err(e) => return rejected(e),
    };

    // Upstream pools are hot-applied; every other field requires a restart.
    let restart_required = {
        let mut before = config.clone();
        let mut after = new_config.clone();
        before.dns.pools.clear();
        after.dns.pools.clear();
        config_differs(&before, &after)
    };

    if let Err(e) = state
        .config_file_persistence
        .save_config_to_file(&new_config, &config_path)
    {
        error!(error = %e, "Failed to save configuration");
        return not_saved(if pools_provided {
            pools_applied_but_not_saved(e)
        } else {
            format!("Failed to save configuration: {e}")
        });
    }

    *config = new_config;
    if restart_required {
        state.mark_restart_pending();
    }
    info!("Configuration updated successfully");

    let message = if restart_required {
        "Configuration saved. Restart the server for the changes to take effect."
    } else if pools_provided {
        "Upstream pools saved and applied immediately. No restart needed."
    } else {
        "Configuration saved successfully."
    };
    (
        StatusCode::OK,
        Json(
            ConfigSaveResponse::success(message)
                .restart_required(restart_required)
                .reload_available(),
        ),
    )
}

#[utoipa::path(
    post,
    path = "/settings",
    tag = "config",
    request_body = SettingsDto,
    responses(
        (status = 200, description = "Save outcome; `success` is false when the update could not be saved", body = ConfigSaveResponse),
        (status = 400, description = "The settings carry an invalid value; nothing was applied", body = ConfigSaveResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_update_settings")]
pub async fn update_settings(
    State(state): State<AppState>,
    Json(request): Json<SettingsDto>,
) -> SaveResponse {
    let config_path = match get_writable_config_path(&state).await {
        Ok(p) => p,
        Err(e) => return e,
    };

    let _writer = state.config_writer.lock().await;
    let mut config = state.config.write().await;
    let mut new_config = config.clone();
    if let Err(e) = apply_settings(&mut new_config, request) {
        return rejected(e);
    }

    // These fields only take effect after a restart, like every non-pool field.
    let restart_required = config_differs(&config, &new_config);

    if let Err(e) = state
        .config_file_persistence
        .save_config_to_file(&new_config, &config_path)
    {
        error!(error = %e, "Failed to save DNS settings");
        return not_saved(format!("Failed to save settings: {e}"));
    }

    *config = new_config;
    if restart_required {
        state.mark_restart_pending();
    }
    info!("DNS settings updated successfully");
    (
        StatusCode::OK,
        Json(
            ConfigSaveResponse::success("DNS settings saved successfully.")
                .restart_required(restart_required),
        ),
    )
}

#[utoipa::path(
    post,
    path = "/config/reload",
    tag = "config",
    responses(
        (status = 200, description = "Reload outcome", body = ConfigSaveResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_reload_config")]
pub async fn reload_config(State(state): State<AppState>) -> Json<ConfigSaveResponse> {
    info!("Config reload requested");

    let Some(reload) = state.reload_config.clone() else {
        error!("No config file found");
        return Json(ConfigSaveResponse::failure("No config file found"));
    };

    match reload.execute().await {
        Ok(()) => Json(ConfigSaveResponse::success(
            "Configuration reloaded successfully",
        )),
        Err(e) => {
            error!(error = %e, "Failed to reload configuration");
            Json(ConfigSaveResponse::failure(format!(
                "Failed to reload configuration: {e}"
            )))
        }
    }
}
