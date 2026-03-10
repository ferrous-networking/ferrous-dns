use crate::{
    dto::{PaginatedQueries, QueryParams, QueryResponse},
    errors::ApiError,
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::use_cases::PagedQueryInput;
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_queries")]
pub async fn get_queries(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<PaginatedQueries>, ApiError> {
    debug!(
        period = %params.period,
        limit = params.limit,
        offset = params.offset,
        cursor = params.cursor,
        domain = ?params.domain,
        category = ?params.category,
        client = ?params.client,
        record_type = ?params.record_type,
        upstream = ?params.upstream,
        "Fetching recent queries"
    );

    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(24.0);

    let input = PagedQueryInput {
        limit: params.limit,
        offset: params.offset,
        period_hours,
        cursor: params.cursor,
        domain: params.domain.as_deref(),
        category: params.category.as_deref(),
        client_ip: params.client.as_deref(),
        record_type: params.record_type.as_deref(),
        upstream: params.upstream.as_deref(),
    };

    let result = state.query.get_queries.execute_paged(&input).await?;

    let data: Vec<QueryResponse> = result
        .queries
        .into_iter()
        .map(|q| QueryResponse {
            timestamp: q.timestamp.unwrap_or_default(),
            domain: q.domain,
            client: q.client_ip.to_string(),
            client_hostname: q.client_hostname,
            record_type: q.record_type.as_str(),
            blocked: q.blocked,
            response_time_us: q.response_time_us,
            cache_hit: q.cache_hit,
            cache_refresh: q.cache_refresh,
            dnssec_status: q.dnssec_status,
            upstream_server: q.upstream_server,
            upstream_pool: q.upstream_pool,
            query_source: q.query_source.as_str(),
            block_source: q.block_source.map(|s| s.to_str()),
            response_status: q.response_status,
        })
        .collect();

    debug!(
        count = data.len(),
        records_total = result.records_total,
        records_filtered = result.records_filtered,
        next_cursor = result.next_cursor,
        "Queries retrieved successfully"
    );

    Ok(Json(PaginatedQueries {
        data,
        total: result.records_filtered,
        records_total: result.records_total,
        limit: params.limit,
        offset: params.offset,
        next_cursor: result.next_cursor,
    }))
}
