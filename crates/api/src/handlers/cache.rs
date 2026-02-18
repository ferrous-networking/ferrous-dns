use crate::{
    dto::{CacheMetricsResponse, CacheStatsQuery, CacheStatsResponse},
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_cache_stats")]
pub async fn get_cache_stats(
    State(state): State<AppState>,
    Query(params): Query<CacheStatsQuery>,
) -> Json<CacheStatsResponse> {
    debug!(period = %params.period, "Fetching cache statistics");

    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(24.0);

    debug!(period_hours = period_hours, "Using period for cache stats");

    match state.get_cache_stats.execute(period_hours).await {
        Ok(stats) => {
            let total_entries = state.cache.size();

            debug!(
                total_entries = total_entries,
                total_hits = stats.total_hits,
                total_misses = stats.total_misses,
                total_refreshes = stats.total_refreshes,
                hit_rate = stats.hit_rate,
                "Cache statistics retrieved"
            );

            Json(CacheStatsResponse {
                total_entries,
                total_hits: stats.total_hits,
                total_misses: stats.total_misses,
                total_refreshes: stats.total_refreshes,
                hit_rate: stats.hit_rate,
                refresh_rate: stats.refresh_rate,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve cache stats");
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

#[instrument(skip(state), name = "api_get_cache_metrics")]
pub async fn get_cache_metrics(State(state): State<AppState>) -> Json<CacheMetricsResponse> {
    debug!("Fetching cache metrics directly from cache");

    let cache = &state.cache;
    let metrics = cache.metrics();

    let hits = metrics.hits.load(std::sync::atomic::Ordering::Relaxed);
    let misses = metrics.misses.load(std::sync::atomic::Ordering::Relaxed);
    let insertions = metrics
        .insertions
        .load(std::sync::atomic::Ordering::Relaxed);
    let evictions = metrics.evictions.load(std::sync::atomic::Ordering::Relaxed);
    let optimistic_refreshes = metrics
        .optimistic_refreshes
        .load(std::sync::atomic::Ordering::Relaxed);
    let lazy_deletions = metrics
        .lazy_deletions
        .load(std::sync::atomic::Ordering::Relaxed);
    let compactions = metrics
        .compactions
        .load(std::sync::atomic::Ordering::Relaxed);
    let batch_evictions = metrics
        .batch_evictions
        .load(std::sync::atomic::Ordering::Relaxed);

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
