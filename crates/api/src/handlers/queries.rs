use crate::{
    dto::{PaginatedQueries, QueryParams, QueryResponse},
    errors::ApiError,
    state::AppState,
    utils::period_hours,
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::ports::PageAt;
use ferrous_dns_application::use_cases::{PagedQueryInput, MAX_QUERY_PAGE_LIMIT};
use ferrous_dns_domain::DnssecStatusFilter;
use tracing::{debug, instrument};

#[utoipa::path(
    get,
    path = "/queries",
    tag = "queries",
    params(QueryParams),
    responses(
        (status = 200, description = "Paginated DNS query log", body = PaginatedQueries),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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
        dnssec_status = ?params.dnssec_status,
        protocol = ?params.protocol,
        "Fetching recent queries"
    );

    let period_hours = period_hours(&params.period);
    let dnssec_status = params
        .dnssec_status
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::parse::<DnssecStatusFilter>)
        .transpose()?;

    let limit = params.limit.clamp(1, MAX_QUERY_PAGE_LIMIT);
    let (page, offset) = match params.cursor {
        Some(cursor) => (PageAt::Cursor(cursor), 0),
        None => (PageAt::Offset(params.offset), params.offset),
    };
    let input = PagedQueryInput {
        limit,
        page,
        period_hours,
        domain: params.domain.as_deref(),
        category: params.category.as_deref(),
        client: params.client.as_deref(),
        record_type: params.record_type.as_deref(),
        upstream: params.upstream.as_deref(),
        dnssec_status,
        dns64: params.dns64,
        protocol: params.protocol.as_deref(),
        ..Default::default()
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
            dnssec_status: q.dnssec_status.map(|s| s.as_str()),
            dns64_synthesized: q.dns64_synthesized,
            answers: q
                .answers
                .map(|a| a.iter().map(|ip| ip.to_string()).collect())
                .unwrap_or_default(),
            upstream_server: q.upstream_server,
            upstream_pool: q.upstream_pool,
            query_source: q.query_source.as_str(),
            protocol: q.protocol.map(|p| p.as_str()),
            block_source: q.block_source.map(|s| s.to_str()),
            response_status: q.response_status,
            coalesced: q.coalesced.map(|role| role.as_str()),
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
        limit,
        offset,
        next_cursor: result.next_cursor,
    }))
}
