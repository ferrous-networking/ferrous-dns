use crate::{
    dto::{PaginatedQueries, QueryParams, QueryResponse},
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_queries")]
pub async fn get_queries(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
) -> Json<PaginatedQueries> {
    debug!(period = %params.period, limit = params.limit, offset = params.offset, "Fetching recent queries");

    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(24.0);

    match state
        .get_queries
        .execute_paged(params.limit, params.offset, period_hours)
        .await
    {
        Ok((queries, total)) => {
            let data: Vec<QueryResponse> = queries
                .into_iter()
                .map(|q| QueryResponse {
                    timestamp: q.timestamp.unwrap_or_default(),
                    domain: q.domain.to_string(),
                    client: q.client_ip.to_string(),
                    record_type: q.record_type.as_str().to_string(),
                    blocked: q.blocked,
                    response_time_ms: q.response_time_ms,
                    cache_hit: q.cache_hit,
                    cache_refresh: q.cache_refresh,
                    dnssec_status: q.dnssec_status.map(|s| s.to_string()),
                    upstream_server: q.upstream_server,
                    query_source: q.query_source.as_str().to_string(),
                    block_source: q.block_source.map(|s| s.to_str().to_string()),
                })
                .collect();

            debug!(
                count = data.len(),
                total = total,
                "Queries retrieved successfully"
            );
            Json(PaginatedQueries {
                data,
                total,
                limit: params.limit,
                offset: params.offset,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve queries");
            Json(PaginatedQueries {
                data: vec![],
                total: 0,
                limit: params.limit,
                offset: params.offset,
            })
        }
    }
}
