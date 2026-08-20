use crate::{
    dto::{
        CacheEntriesQuery, CacheEntryResponse, CacheMetricsResponse, CacheStatsQuery,
        CacheStatsResponse, DeleteCacheEntryQuery, PaginatedCacheEntries,
    },
    errors::ApiError,
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use ferrous_dns_application::ports::{CacheEntryQuery, CacheEntrySnapshot};
use ferrous_dns_domain::{DomainError, RecordType};
use tracing::{debug, instrument};

/// Upper bound on how many cache entries a single listing request may return.
const MAX_CACHE_ENTRIES_LIMIT: u32 = 500;

#[utoipa::path(
    get,
    path = "/cache/stats",
    tag = "cache",
    params(CacheStatsQuery),
    responses(
        (status = 200, description = "Cache statistics for the period", body = CacheStatsResponse),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    get,
    path = "/cache/metrics",
    tag = "cache",
    responses(
        (status = 200, description = "Live cache metrics snapshot", body = CacheMetricsResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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
        stale_hits: snapshot.stale_hits,
        lazy_deletions: snapshot.lazy_deletions,
        compactions: snapshot.compactions,
        batch_evictions: snapshot.batch_evictions,
        hit_rate: snapshot.hit_rate,
        transient_upstream_errors: snapshot.transient_upstream_errors,
    })
}

#[utoipa::path(
    get,
    path = "/cache/entries",
    tag = "cache",
    params(CacheEntriesQuery),
    responses(
        (status = 200, description = "Cached DNS entries", body = PaginatedCacheEntries),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_cache_entries")]
pub async fn get_cache_entries(
    State(state): State<AppState>,
    Query(params): Query<CacheEntriesQuery>,
) -> Json<PaginatedCacheEntries> {
    let limit = params.limit.clamp(1, MAX_CACHE_ENTRIES_LIMIT);

    let query = CacheEntryQuery {
        domain: params.domain.filter(|domain| !domain.is_empty()),
        record_type: params
            .record_type
            .as_deref()
            .and_then(|value| value.parse::<RecordType>().ok()),
        sort: params
            .sort
            .as_deref()
            .and_then(|value| value.parse().ok())
            .unwrap_or_default(),
        order: params
            .order
            .as_deref()
            .and_then(|value| value.parse().ok())
            .unwrap_or_default(),
        limit: limit as usize,
        offset: params.offset as usize,
    };

    let page = state.dns.cache.list_entries(&query);

    debug!(
        returned = page.entries.len(),
        total = page.total,
        records_total = page.records_total,
        "Cache entries listed"
    );

    Json(PaginatedCacheEntries {
        data: page.entries.iter().map(to_entry_response).collect(),
        total: page.total,
        records_total: page.records_total,
        limit,
        offset: params.offset,
    })
}

#[utoipa::path(
    delete,
    path = "/cache/entries",
    tag = "cache",
    params(DeleteCacheEntryQuery),
    responses(
        (status = 204, description = "Cache entry removed"),
        (status = 400, description = "Unknown record type"),
        (status = 404, description = "Cache entry not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_delete_cache_entry")]
pub async fn delete_cache_entry(
    State(state): State<AppState>,
    Query(params): Query<DeleteCacheEntryQuery>,
) -> Result<StatusCode, ApiError> {
    let record_type = params.record_type.parse::<RecordType>().map_err(|_| {
        DomainError::InvalidInput(format!("unknown record type: {}", params.record_type))
    })?;

    if !state.dns.cache.remove_record(&params.domain, &record_type) {
        return Err(ApiError(DomainError::NotFound(format!(
            "cache entry {} {}",
            params.domain,
            record_type.as_str()
        ))));
    }

    debug!(domain = %params.domain, record_type = %record_type, "Cache entry removed");

    Ok(StatusCode::NO_CONTENT)
}

fn to_entry_response(entry: &CacheEntrySnapshot) -> CacheEntryResponse {
    CacheEntryResponse {
        domain: entry.domain.clone(),
        record_type: entry.record_type.as_str(),
        answers: entry
            .answers
            .iter()
            .map(|address| address.to_string())
            .collect(),
        canonical_name: entry.canonical_name.clone(),
        dnssec_status: entry.dnssec_status.map(|status| status.as_str()),
        ttl: entry.ttl,
        remaining_ttl: entry.remaining_ttl,
        cached_at: entry.cached_at_secs,
        expires_at: if entry.is_permanent {
            None
        } else {
            Some(entry.expires_at_secs)
        },
        hits: entry.hits,
        last_access: entry.last_access_secs,
        permanent: entry.is_permanent,
        stale: entry.is_stale,
    }
}
