use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use chrono::DateTime;

use crate::{
    dto::queries::{
        map_query_status, PiholeClientRef, PiholeQueryEntry, QueriesResponse, SuggestionsResponse,
    },
    errors::PiholeApiError,
    handlers::stats::STATS_PERIOD_HOURS,
    state::PiholeAppState,
};

const DEFAULT_LIMIT: u32 = 100;

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub length: Option<u32>,
    pub start: Option<u32>,
    pub cursor: Option<i64>,
    pub domain: Option<String>,
}

/// Pi-hole v6 GET /api/queries
pub async fn get_queries(
    State(state): State<PiholeAppState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueriesResponse>, PiholeApiError> {
    let limit = params.length.unwrap_or(DEFAULT_LIMIT);
    let offset = params.start.unwrap_or(0);

    let (logs, total, next_cursor) = state
        .query
        .get_recent_queries
        .execute_paged(
            limit,
            offset,
            STATS_PERIOD_HOURS,
            params.cursor,
            params.domain.as_deref(),
        )
        .await?;

    let queries: Vec<PiholeQueryEntry> = logs
        .into_iter()
        .map(|q| PiholeQueryEntry {
            id: q.id.unwrap_or(0),
            time: q
                .timestamp
                .as_deref()
                .and_then(|ts| {
                    let s = if ts.ends_with('Z') {
                        ts.to_string()
                    } else {
                        format!("{}Z", ts.replace(' ', "T"))
                    };
                    DateTime::parse_from_rfc3339(&s).ok()
                })
                .map(|dt| dt.timestamp() as f64)
                .unwrap_or(0.0),
            r#type: format!("{:?}", q.record_type),
            domain: q.domain.to_string(),
            client: PiholeClientRef {
                ip: q.client_ip.to_string(),
                name: q
                    .client_hostname
                    .as_ref()
                    .map(|h| h.to_string())
                    .unwrap_or_default(),
            },
            status: map_query_status(q.blocked, q.cache_hit, q.block_source.as_ref()),
            dnssec: q.dnssec_status.unwrap_or_default().to_string(),
            reply: q
                .response_status
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            response_time: q.response_time_us.map(|t| t as f64 / 1000.0).unwrap_or(0.0),
            upstream: q
                .upstream_server
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default(),
        })
        .collect();

    Ok(Json(QueriesResponse {
        records_total: total,
        records_filtered: total,
        cursor: next_cursor,
        queries,
    }))
}

/// Pi-hole v6 GET /api/queries/suggestions
///
/// Returns domain suggestions based on recent queries.
pub async fn get_suggestions(
    State(state): State<PiholeAppState>,
) -> Result<Json<SuggestionsResponse>, PiholeApiError> {
    let logs = state
        .query
        .get_recent_queries
        .execute(200, STATS_PERIOD_HOURS)
        .await?;

    let mut domains: Vec<String> = logs.into_iter().map(|q| q.domain.to_string()).collect();
    domains.sort();
    domains.dedup();
    domains.truncate(50);

    Ok(Json(SuggestionsResponse {
        suggestions: domains,
    }))
}
