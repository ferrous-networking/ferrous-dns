use crate::{
    dto::{StatsQuery, StatsResponse, TopType, TypeDistribution},
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{error, instrument};

const DEFAULT_PERIOD_HOURS: f32 = 24.0;
const TOP_TYPES_LIMIT: usize = 10;

#[instrument(skip(state), name = "api_get_stats")]
pub async fn get_stats(
    State(state): State<AppState>,
    Query(params): Query<StatsQuery>,
) -> Json<StatsResponse> {
    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(DEFAULT_PERIOD_HOURS);

    match state.get_stats.execute(period_hours).await {
        Ok(stats) => {
            let queries_by_type = stats
                .queries_by_type
                .iter()
                .map(|(rt, count)| (rt.as_str().to_string(), *count))
                .collect();

            let most_queried_type = stats.most_queried_type.map(|rt| rt.as_str().to_string());

            let record_type_distribution = stats
                .record_type_distribution
                .iter()
                .map(|(rt, pct)| TypeDistribution {
                    record_type: rt.as_str().to_string(),
                    percentage: *pct,
                })
                .collect();

            let top_10_types = stats
                .top_types(TOP_TYPES_LIMIT)
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
                source_stats: stats.source_stats,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve statistics");
            Json(StatsResponse::default())
        }
    }
}
