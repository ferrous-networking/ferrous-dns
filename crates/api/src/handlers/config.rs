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

/// GET /api/settings - Get current DNS settings
#[instrument(skip(state), name = "api_get_settings")]
pub async fn get_settings(State(state): State<AppState>) -> Json<crate::dto::SettingsDto> {
    info!("Fetching DNS settings");

    let config = state.config.read().await;

    // Extract conditional forwarding settings
    let (cidr, router, domain) = extract_conditional_forward_config(&config.dns);

    Json(crate::dto::SettingsDto {
        never_forward_non_fqdn: config.dns.block_non_fqdn,
        never_forward_reverse_lookups: config.dns.block_private_ptr,
        conditional_forwarding_enabled: !config.dns.conditional_forwarding.is_empty()
            || config.dns.conditional_forward_network.is_some(),
        local_network_cidr: cidr,
        router_ip: router,
        local_domain: domain,
    })
}

/// Extract simplified conditional forwarding config from DnsConfig
fn extract_conditional_forward_config(
    dns_config: &ferrous_dns_domain::DnsConfig,
) -> (String, String, String) {
    // Priority 1: Check simplified fields first
    if let (Some(network), Some(router)) = (
        &dns_config.conditional_forward_network,
        &dns_config.conditional_forward_router,
    ) {
        let domain = dns_config.local_domain.clone().unwrap_or_default();
        return (network.clone(), router.clone(), domain);
    }

    // Priority 2: Check first rule in conditional_forwarding array
    if let Some(rule) = dns_config.conditional_forwarding.first() {
        // Extract router IP from server string (remove :53 port)
        let router_ip = rule.server.split(':').next().unwrap_or("").to_string();

        // Use local_domain if set, otherwise use rule domain
        let domain = dns_config
            .local_domain
            .clone()
            .or_else(|| Some(rule.domain.clone()))
            .unwrap_or_default();

        // Note: Cannot reliably infer CIDR from domain, leave empty
        let cidr = String::new();

        return (cidr, router_ip, domain);
    }

    // Priority 3: Default - empty values
    (String::new(), String::new(), String::new())
}

/// POST /api/settings - Update DNS settings
#[instrument(skip(state), name = "api_update_settings")]
pub async fn update_settings(
    State(state): State<AppState>,
    Json(req): Json<crate::dto::SettingsDto>,
) -> Json<crate::dto::SettingsUpdateResponse> {
    info!("Updating DNS settings");

    // Step 1: Validate inputs
    if req.conditional_forwarding_enabled {
        // Validate CIDR format
        if req.local_network_cidr.is_empty() {
            return Json(crate::dto::SettingsUpdateResponse {
                success: false,
                message: "Local network CIDR is required when conditional forwarding is enabled"
                    .to_string(),
                settings: req,
            });
        }

        if !is_valid_cidr(&req.local_network_cidr) {
            return Json(crate::dto::SettingsUpdateResponse {
                success: false,
                message: format!(
                    "Invalid CIDR format: '{}'. Use format like '192.168.0.0/24'",
                    req.local_network_cidr
                ),
                settings: req,
            });
        }

        // Validate router IP
        if req.router_ip.is_empty() {
            return Json(crate::dto::SettingsUpdateResponse {
                success: false,
                message: "Router IP is required when conditional forwarding is enabled".to_string(),
                settings: req,
            });
        }

        if req.router_ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Json(crate::dto::SettingsUpdateResponse {
                success: false,
                message: format!("Invalid router IP address: '{}'", req.router_ip),
                settings: req,
            });
        }
    }

    // Step 2: Update config
    {
        let mut config = state.config.write().await;

        // Update query filters
        config.dns.block_non_fqdn = req.never_forward_non_fqdn;
        config.dns.block_private_ptr = req.never_forward_reverse_lookups;

        // Update local domain
        config.dns.local_domain = if req.local_domain.is_empty() {
            None
        } else {
            Some(req.local_domain.clone())
        };

        // Update conditional forwarding
        if req.conditional_forwarding_enabled {
            // Store simplified format
            config.dns.conditional_forward_network = Some(req.local_network_cidr.clone());
            config.dns.conditional_forward_router = Some(req.router_ip.clone());

            // Also create rule in conditional_forwarding array
            let domain = if req.local_domain.is_empty() {
                extract_domain_from_cidr(&req.local_network_cidr)
            } else {
                req.local_domain.clone()
            };

            config.dns.conditional_forwarding = vec![ferrous_dns_domain::ConditionalForward {
                domain,
                server: format!("{}:53", req.router_ip),
                record_types: None,
            }];
        } else {
            // Clear conditional forwarding
            config.dns.conditional_forward_network = None;
            config.dns.conditional_forward_router = None;
            config.dns.conditional_forwarding.clear();
        }

        // Step 3: Backup and save to file
        if let Err(e) = save_config_with_backup(&config).await {
            error!(error = %e, "Failed to save settings");
            return Json(crate::dto::SettingsUpdateResponse {
                success: false,
                message: format!("Failed to save settings: {}", e),
                settings: req,
            });
        }

        info!("Settings saved to config file");
    }

    // Step 4: Apply settings to resolver (without restart)
    let restart_required = match apply_settings_to_resolver(&state).await {
        Ok(requires_restart) => requires_restart,
        Err(e) => {
            error!(error = %e, "Failed to apply settings to resolver");
            return Json(crate::dto::SettingsUpdateResponse {
                success: false,
                message: format!("Settings saved but failed to apply: {}", e),
                settings: req,
            });
        }
    };

    let message = if restart_required {
        "DNS settings updated successfully. Please restart the server for all changes to take effect.".to_string()
    } else {
        "DNS settings updated successfully.".to_string()
    };

    info!(restart_required, "Settings applied successfully");

    Json(crate::dto::SettingsUpdateResponse {
        success: true,
        message,
        settings: req,
    })
}

/// Validate CIDR notation format
fn is_valid_cidr(cidr: &str) -> bool {
    // Format: xxx.xxx.xxx.xxx/yy
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    // Validate IP part
    if parts[0].parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }

    // Validate prefix length (0-32)
    if let Ok(prefix) = parts[1].parse::<u8>() {
        prefix <= 32
    } else {
        false
    }
}

/// Extract domain name from CIDR notation
/// Returns "local" as default since CIDR alone doesn't indicate domain
fn extract_domain_from_cidr(_cidr: &str) -> String {
    // Simple heuristic: use "local" as default
    // User should set local_domain explicitly for better naming
    "local".to_string()
}

/// Save config to file with automatic backup
async fn save_config_with_backup(config: &ferrous_dns_domain::Config) -> Result<(), String> {
    let config_path =
        ferrous_dns_domain::Config::get_config_path().ok_or("No config file path found")?;

    // Create backup of original config
    let backup_path = format!("{}.backup", config_path);
    if std::path::Path::new(&config_path).exists() {
        std::fs::copy(&config_path, &backup_path)
            .map_err(|e| format!("Failed to create backup: {}", e))?;
        debug!("Created backup at: {}", backup_path);
    }

    // Serialize config to TOML
    let toml_string =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {}", e))?;

    // Write to file
    std::fs::write(&config_path, toml_string)
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    info!("Config saved to: {}", config_path);
    Ok(())
}

/// Apply settings to resolver without restarting server
/// Returns true if server restart is required
async fn apply_settings_to_resolver(state: &AppState) -> Result<bool, String> {
    let config = state.config.read().await;

    // Note: For MVP, query filter changes require server restart
    // In future versions, we can implement hot-reload with interior mutability

    info!(
        block_non_fqdn = config.dns.block_non_fqdn,
        block_private_ptr = config.dns.block_private_ptr,
        conditional_forwarding = !config.dns.conditional_forwarding.is_empty(),
        "Settings will apply on next server restart"
    );

    // Return true to indicate restart is required
    Ok(true)
}
