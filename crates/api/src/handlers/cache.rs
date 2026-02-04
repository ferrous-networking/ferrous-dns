use crate::{
    dto::{CacheMetricsResponse, CacheStatsResponse},
    state::AppState,
};
use axum::{extract::State, Json};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_cache_stats")]
pub async fn get_cache_stats(State(state): State<AppState>) -> Json<CacheStatsResponse> {
    debug!("Fetching cache statistics");

    match state.get_queries.execute(100000).await {
        Ok(queries) => {
            let total_hits = queries
                .iter()
                .filter(|q| q.cache_hit && !q.cache_refresh)
                .count() as u64;
            let total_refreshes = queries.iter().filter(|q| q.cache_refresh).count() as u64;
            let total_misses = queries
                .iter()
                .filter(|q| !q.cache_hit && !q.cache_refresh && !q.blocked)
                .count() as u64;
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
