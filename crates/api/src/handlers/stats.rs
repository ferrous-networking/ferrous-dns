use crate::{dto::StatsResponse, state::AppState};
use axum::{extract::State, Json};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_stats")]
pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    debug!("Fetching query statistics");

    match state.get_stats.execute().await {
        Ok(stats) => {
            debug!(
                queries_total = stats.queries_total,
                queries_blocked = stats.queries_blocked,
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
            Json(StatsResponse::default())
        }
    }
}
