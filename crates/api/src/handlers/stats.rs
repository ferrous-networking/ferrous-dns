use crate::{
    dto::{StatsResponse, TopType, TypeDistribution},
    state::AppState,
};
use axum::{extract::State, Json};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_stats")]
pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    debug!("Fetching query statistics with Phase 4 analytics");

    match state.get_stats.execute().await {
        Ok(stats) => {
            debug!(
                queries_total = stats.queries_total,
                queries_blocked = stats.queries_blocked,
                most_queried_type = ?stats.most_queried_type,
                type_count = stats.queries_by_type.len(),
                "Statistics with analytics retrieved successfully"
            );

            // Convert HashMap<RecordType, u64> to HashMap<String, u64>
            let queries_by_type = stats
                .queries_by_type
                .iter()
                .map(|(rt, count)| (rt.as_str().to_string(), *count))
                .collect();

            // Convert most_queried_type
            let most_queried_type = stats.most_queried_type.map(|rt| rt.as_str().to_string());

            // Convert distribution
            let record_type_distribution = stats
                .record_type_distribution
                .iter()
                .map(|(rt, pct)| TypeDistribution {
                    record_type: rt.as_str().to_string(),
                    percentage: *pct,
                })
                .collect();

            // Get top 10 types
            let top_10_types = stats
                .top_types(10)
                .into_iter()
                .map(|(rt, count)| TopType {
                    record_type: rt.as_str().to_string(),
                    count,
                })
                .collect();

            Json(StatsResponse {
                queries_total: stats.queries_total,
                queries_blocked: stats.queries_blocked,
                clients: stats.unique_clients,
                uptime: stats.uptime_seconds,
                cache_hit_rate: stats.cache_hit_rate,
                avg_query_time_ms: stats.avg_query_time_ms,
                avg_cache_time_ms: stats.avg_cache_time_ms,
                avg_upstream_time_ms: stats.avg_upstream_time_ms,
                queries_by_type,
                most_queried_type,
                record_type_distribution,
                top_10_types,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve statistics");
            Json(StatsResponse::default())
        }
    }
}
