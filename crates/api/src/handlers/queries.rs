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
    debug!(
        period = %params.period,
        limit = params.limit,
        offset = params.offset,
        cursor = params.cursor,
        "Fetching recent queries"
    );

    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(24.0);

    match state
        .get_queries
        .execute_paged(params.limit, params.offset, period_hours, params.cursor)
        .await
    {
        Ok((queries, total, next_cursor)) => {
            let data: Vec<QueryResponse> = queries
                .into_iter()
                .map(|q| QueryResponse {
                    timestamp: q.timestamp.unwrap_or_default(),
                    domain: q.domain,
                    client: q.client_ip.to_string(),
                    client_hostname: q.client_hostname,
                    record_type: q.record_type.as_str().to_string(),
                    blocked: q.blocked,
                    response_time_us: q.response_time_us,
                    cache_hit: q.cache_hit,
                    cache_refresh: q.cache_refresh,
                    dnssec_status: q.dnssec_status.map(|s| s.to_string()),
                    upstream_server: q.upstream_server,
                    query_source: q.query_source.as_str().to_string(),
                    block_source: q.block_source.map(|s| s.to_str().to_string()),
                    response_status: q.response_status.map(|s| s.to_string()),
                })
                .collect();

            debug!(
                count = data.len(),
                total = total,
                next_cursor = next_cursor,
                "Queries retrieved successfully"
            );
            Json(PaginatedQueries {
                data,
                total,
                limit: params.limit,
                offset: params.offset,
                next_cursor,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve queries");
            Json(PaginatedQueries {
                data: vec![],
                total: 0,
                limit: params.limit,
                offset: params.offset,
                next_cursor: None,
            })
        }
    }
}
