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
    pub cache_ttl: u64,
    pub dnssec_enabled: bool,
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
    debug!("Fetching recent queries");

    match state.get_queries.execute(100).await {
        Ok(queries) => {
            debug!(count = queries.len(), "Queries retrieved successfully");

            let response = queries
                .into_iter()
                .map(|q| QueryResponse {
                    timestamp: q.timestamp.unwrap_or_default(),
                    domain: q.domain,
                    client: q.client_ip.to_string(),
                    record_type: q.record_type.as_str().to_string(),
                    blocked: q.blocked,
                    response_time_ms: q.response_time_ms,
                    cache_hit: q.cache_hit,
                })
                .collect();

            Json(response)
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
                "message": "Configuration updated successfully. Restart server to apply changes."
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
