use crate::{
    dto::{CacheMetricsResponse, CacheStatsQuery, CacheStatsResponse},
    errors::ApiError,
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_cache_stats")]
pub async fn get_cache_stats(
    State(state): State<AppState>,
    Query(params): Query<CacheStatsQuery>,
) -> Result<Json<CacheStatsResponse>, ApiError> {
    debug!(period = %params.period, "Fetching cache statistics");

    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(24.0);

    debug!(period_hours = period_hours, "Using period for cache stats");

    let stats = state.query.get_cache_stats.execute(period_hours).await?;
    let total_entries = state.dns.cache.cache_size();

    debug!(
        total_entries = total_entries,
        total_hits = stats.total_hits,
        total_misses = stats.total_misses,
        total_refreshes = stats.total_refreshes,
        hit_rate = stats.hit_rate,
        "Cache statistics retrieved"
    );

    Ok(Json(CacheStatsResponse {
        total_entries,
        total_hits: stats.total_hits,
        total_misses: stats.total_misses,
        total_refreshes: stats.total_refreshes,
        hit_rate: stats.hit_rate,
        refresh_rate: stats.refresh_rate,
    }))
}

#[instrument(skip(state), name = "api_get_cache_metrics")]
pub async fn get_cache_metrics(State(state): State<AppState>) -> Json<CacheMetricsResponse> {
    debug!("Fetching cache metrics directly from cache");

    let snapshot = state.dns.cache.cache_metrics_snapshot();

    debug!(
        total_entries = snapshot.total_entries,
        hits = snapshot.hits,
        misses = snapshot.misses,
        optimistic_refreshes = snapshot.optimistic_refreshes,
        hit_rate = snapshot.hit_rate,
        "Cache metrics retrieved"
    );

    Json(CacheMetricsResponse {
        total_entries: snapshot.total_entries,
        hits: snapshot.hits,
        misses: snapshot.misses,
        insertions: snapshot.insertions,
        evictions: snapshot.evictions,
        optimistic_refreshes: snapshot.optimistic_refreshes,
        lazy_deletions: snapshot.lazy_deletions,
        compactions: snapshot.compactions,
        batch_evictions: snapshot.batch_evictions,
        hit_rate: snapshot.hit_rate,
    })
}
