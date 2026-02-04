use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument};

use crate::state::AppState;

#[derive(Serialize)]
pub struct StatsResponse {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub clients: u64,
    pub uptime: u64,
    pub cache_hit_rate: f64,
    pub avg_query_time_ms: f64,
    pub avg_cache_time_ms: f64,
    pub avg_upstream_time_ms: f64,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub timestamp: String,
    pub domain: String,
    pub client: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub blocked: bool,
    pub response_time_ms: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,  // NEW
    pub dnssec_status: Option<String>,  // NEW: DNSSEC validation status
}

#[derive(Serialize)]
pub struct CacheStatsResponse {
    pub total_entries: usize,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_refreshes: u64,
    pub hit_rate: f64,
    pub refresh_rate: f64,
}

#[derive(Serialize)]
pub struct CacheMetricsResponse {
    pub total_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub optimistic_refreshes: u64,
    pub lazy_deletions: u64,
    pub compactions: u64,
    pub batch_evictions: u64,
    pub hit_rate: f64,
}

#[derive(Serialize)]
pub struct BlocklistResponse {
    pub domain: String,
    pub added_at: String,
}

#[derive(Serialize)]
pub struct ConfigResponse {
    pub server: ServerConfigResponse,
    pub dns: DnsConfigResponse,
    pub blocking: BlockingConfigResponse,
    pub logging: LoggingConfigResponse,
    pub database: DatabaseConfigResponse,
    pub config_path: Option<String>,
    pub writable: bool,
}

#[derive(Serialize)]
pub struct ServerConfigResponse {
    pub dns_port: u16,
    pub web_port: u16,
    pub bind_address: String,
}

#[derive(Serialize)]
pub struct DnsConfigResponse {
    pub upstream_servers: Vec<String>,
    pub query_timeout: u64,
    pub cache_enabled: bool,
    pub cache_ttl: u32,  // Changed from u64 to u32
    pub dnssec_enabled: bool,
    pub cache_eviction_strategy: String,
    pub cache_max_entries: usize,
    pub cache_min_hit_rate: f64,
    pub cache_min_frequency: u64,
    pub cache_min_lfuk_score: f64,
    pub cache_optimistic_refresh: bool,
    pub cache_adaptive_thresholds: bool,
}

#[derive(Serialize)]
pub struct BlockingConfigResponse {
    pub enabled: bool,
    pub custom_blocked: Vec<String>,
    pub whitelist: Vec<String>,
}

#[derive(Serialize)]
pub struct LoggingConfigResponse {
    pub level: String,
}

#[derive(Serialize)]
pub struct DatabaseConfigResponse {
    pub path: String,
    pub log_queries: bool,
}

#[derive(Deserialize, Debug)]
pub struct UpdateConfigRequest {
    pub dns: Option<DnsConfigUpdate>,
    pub blocking: Option<BlockingConfigUpdate>,
}

#[derive(Deserialize, Debug)]
pub struct DnsConfigUpdate {
    pub upstream_servers: Option<Vec<String>>,
    pub cache_enabled: Option<bool>,
    pub dnssec_enabled: Option<bool>,
    pub cache_eviction_strategy: Option<String>,
    pub cache_max_entries: Option<usize>,
    pub cache_min_hit_rate: Option<f64>,
    pub cache_min_frequency: Option<u64>,
    pub cache_min_lfuk_score: Option<f64>,
    pub cache_optimistic_refresh: Option<bool>,
    pub cache_adaptive_thresholds: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct BlockingConfigUpdate {
    pub enabled: Option<bool>,
    pub custom_blocked: Option<Vec<String>>,
    pub whitelist: Option<Vec<String>>,
}

#[instrument(skip_all)]
pub async fn health_check() -> &'static str {
    info!("Health check requested");
    "OK"
}

#[instrument(skip(state), name = "api_get_stats")]
pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    debug!("Fetching query statistics");

    match state.get_stats.execute().await {
        Ok(stats) => {
            debug!(
                queries_total = stats.queries_total,
                queries_blocked = stats.queries_blocked,
                unique_clients = stats.unique_clients,
                uptime_seconds = stats.uptime_seconds,
                cache_hit_rate = stats.cache_hit_rate,
                avg_query_time_ms = stats.avg_query_time_ms,
                "Statistics retrieved successfully"
            );

            Json(StatsResponse {
                queries_total: stats.queries_total,
                queries_blocked: stats.queries_blocked,
                clients: stats.unique_clients,
                uptime: stats.uptime_seconds,
                cache_hit_rate: stats.cache_hit_rate,
                avg_query_time_ms: stats.avg_query_time_ms,
                avg_cache_time_ms: stats.avg_cache_time_ms,
                avg_upstream_time_ms: stats.avg_upstream_time_ms,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve statistics");

            Json(StatsResponse {
                queries_total: 0,
                queries_blocked: 0,
                clients: 0,
                uptime: 0,
                cache_hit_rate: 0.0,
                avg_query_time_ms: 0.0,
                avg_cache_time_ms: 0.0,
                avg_upstream_time_ms: 0.0,
            })
        }
    }
}

#[instrument(skip(state), name = "api_get_queries")]
pub async fn get_queries(State(state): State<AppState>) -> Json<Vec<QueryResponse>> {
    debug!("Fetching recent queries (last 24 hours)");

    // Get queries from last 24 hours (1440 minutes = 24 hours * 60)
    match state.get_queries.execute(10000).await {  // Get lots of queries
        Ok(queries) => {
            // Filter to last 24 hours
            let now = chrono::Utc::now();
            let twenty_four_hours_ago = now - chrono::Duration::hours(24);
            
            let filtered: Vec<QueryResponse> = queries
                .into_iter()
                .filter_map(|q| {
                    // Parse timestamp
                    if let Some(ts) = &q.timestamp {
                        if let Ok(query_time) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
                            let query_time_utc = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(query_time, chrono::Utc);
                            
                            // Only include if within last 24 hours
                            if query_time_utc >= twenty_four_hours_ago {
                                return Some(QueryResponse {
                                    timestamp: q.timestamp.unwrap_or_default(),
                                    domain: q.domain,
                                    client: q.client_ip.to_string(),
                                    record_type: q.record_type.as_str().to_string(),
                                    blocked: q.blocked,
                                    response_time_ms: q.response_time_ms,
                                    cache_hit: q.cache_hit,
                                    cache_refresh: q.cache_refresh,
                                    dnssec_status: q.dnssec_status,  // NEW
                                });
                            }
                        }
                    }
                    None
                })
                .collect();

            debug!(count = filtered.len(), "Queries from last 24h retrieved successfully");
            Json(filtered)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve queries");
            Json(vec![])
        }
    }
}

#[instrument(skip(state), name = "api_get_blocklist")]
pub async fn get_blocklist(State(state): State<AppState>) -> Json<Vec<BlocklistResponse>> {
    debug!("Fetching blocklist");

    match state.get_blocklist.execute().await {
        Ok(domains) => {
            debug!(count = domains.len(), "Blocklist retrieved successfully");

            let response = domains
                .into_iter()
                .map(|d| BlocklistResponse {
                    domain: d.domain,
                    added_at: d.added_at.unwrap_or_default(),
                })
                .collect();

            Json(response)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve blocklist");
            Json(vec![])
        }
    }
}

#[instrument(skip(state), name = "api_get_cache_stats")]
pub async fn get_cache_stats(State(state): State<AppState>) -> Json<CacheStatsResponse> {
    debug!("Fetching cache statistics");

    // Get all queries to calculate cache stats
    match state.get_queries.execute(100000).await {
        Ok(queries) => {
            let total_hits = queries.iter().filter(|q| q.cache_hit && !q.cache_refresh).count() as u64;
            let total_refreshes = queries.iter().filter(|q| q.cache_refresh).count() as u64;
            let total_misses = queries.iter().filter(|q| !q.cache_hit && !q.cache_refresh && !q.blocked).count() as u64;
            let total_queries = total_hits + total_misses;
            
            let hit_rate = if total_queries > 0 {
                (total_hits as f64 / total_queries as f64) * 100.0
            } else {
                0.0
            };
            
            let refresh_rate = if total_hits > 0 {
                (total_refreshes as f64 / total_hits as f64) * 100.0
            } else {
                0.0
            };

            // Get actual cache size
            let total_entries = state.cache.size();

            debug!(
                total_entries = total_entries,
                total_hits = total_hits,
                total_misses = total_misses,
                total_refreshes = total_refreshes,
                hit_rate = hit_rate,
                "Cache statistics calculated"
            );

            Json(CacheStatsResponse {
                total_entries,
                total_hits,
                total_misses,
                total_refreshes,
                hit_rate,
                refresh_rate,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to calculate cache stats");
            Json(CacheStatsResponse {
                total_entries: 0,
                total_hits: 0,
                total_misses: 0,
                total_refreshes: 0,
                hit_rate: 0.0,
                refresh_rate: 0.0,
            })
        }
    }
}

#[instrument(skip(state), name = "api_get_config")]
pub async fn get_config(State(state): State<AppState>) -> Json<ConfigResponse> {
    debug!("Fetching current configuration");

    let config = state.config.read().await;
    let config_path = ferrous_dns_domain::Config::get_config_path();

    // Check if config file is writable
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

    // Check write permissions
    if let Ok(metadata) = std::fs::metadata(&config_path) {
        if metadata.permissions().readonly() {
            error!("Config file is read-only");
            return Json(serde_json::json!({
                "success": false,
                "error": "Permission denied: Config file is read-only. Please check file permissions."
            }));
        }
    }

    // Update config
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

    // Save to file
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

#[derive(Serialize)]
pub struct HostnameResponse {
    pub hostname: String,
}

#[instrument(skip_all, name = "api_get_hostname")]
pub async fn get_hostname() -> Json<HostnameResponse> {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "DNS Server".to_string());
    
    Json(HostnameResponse { hostname })
}

#[instrument(skip(state), name = "api_get_cache_metrics")]
pub async fn get_cache_metrics(State(state): State<AppState>) -> Json<CacheMetricsResponse> {
    debug!("Fetching cache metrics directly from cache");

    let cache = &state.cache;
    let metrics = cache.metrics();

    // Read atomic counters
    let hits = metrics.hits.load(std::sync::atomic::Ordering::Relaxed);
    let misses = metrics.misses.load(std::sync::atomic::Ordering::Relaxed);
    let insertions = metrics.insertions.load(std::sync::atomic::Ordering::Relaxed);
    let evictions = metrics.evictions.load(std::sync::atomic::Ordering::Relaxed);
    let optimistic_refreshes = metrics.optimistic_refreshes.load(std::sync::atomic::Ordering::Relaxed);
    let lazy_deletions = metrics.lazy_deletions.load(std::sync::atomic::Ordering::Relaxed);
    let compactions = metrics.compactions.load(std::sync::atomic::Ordering::Relaxed);
    let batch_evictions = metrics.batch_evictions.load(std::sync::atomic::Ordering::Relaxed);

    let hit_rate = metrics.hit_rate();
    let total_entries = cache.size();

    debug!(
        total_entries = total_entries,
        hits = hits,
        misses = misses,
        optimistic_refreshes = optimistic_refreshes,
        hit_rate = hit_rate,
        "Cache metrics retrieved"
    );

    Json(CacheMetricsResponse {
        total_entries,
        hits,
        misses,
        insertions,
        evictions,
        optimistic_refreshes,
        lazy_deletions,
        compactions,
        batch_evictions,
        hit_rate,
    })
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

    // Reload config from file
    let new_config = match ferrous_dns_domain::Config::load(Some(&config_path), Default::default()) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(error = %e, "Failed to reload config from file");
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to reload config: {}", e)
            }));
        }
    };

    // Update config in state
    {
        let mut config = state.config.write().await;
        *config = new_config.clone();
        info!("Configuration reloaded from file");
    }

    // Clear cache
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
