use axum::{extract::State, Json};
use serde::Serialize;
use tracing::{debug, error, info, instrument};

use crate::state::AppState;

#[derive(Serialize)]
pub struct StatsResponse {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub clients: u64,
    pub uptime: u64,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub timestamp: String,
    pub domain: String,
    pub client: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub blocked: bool,
}

#[derive(Serialize)]
pub struct BlocklistResponse {
    pub domain: String,
    pub added_at: String,
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
                "Statistics retrieved successfully"
            );

            Json(StatsResponse {
                queries_total: stats.queries_total,
                queries_blocked: stats.queries_blocked,
                clients: stats.unique_clients,
                uptime: stats.uptime_seconds,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve statistics");

            Json(StatsResponse {
                queries_total: 0,
                queries_blocked: 0,
                clients: 0,
                uptime: 0,
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
