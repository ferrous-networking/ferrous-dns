use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::{
    dto::queries::{
        map_query_status, PiholeClientRef, PiholeEde, PiholeQueryEntry, PiholeReply,
        QueriesResponse, SuggestionsResponse,
    },
    errors::PiholeApiError,
    handlers::stats::STATS_PERIOD_HOURS,
    state::PiholeAppState,
    timestamp::parse_unix_epoch,
};

const DEFAULT_LIMIT: u32 = 100;
const SUGGESTIONS_QUERY_LIMIT: u32 = 200;
const MAX_SUGGESTIONS_PER_CATEGORY: usize = 50;

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub length: Option<u32>,
    pub start: Option<u32>,
    pub cursor: Option<i64>,
    pub domain: Option<String>,
    pub client: Option<String>,
    pub status: Option<String>,
    pub draw: Option<u32>,
}

/// Maps Pi-hole numeric status codes and v6 string names to query categories.
fn pihole_status_to_category(status: &str) -> Option<&'static str> {
    match status {
        "1" | "4" | "5" | "6" | "7" | "9" => Some("blocked"),
        "2" | "8" => Some("upstream"),
        "3" => Some("cache"),

        "GRAVITY"
        | "REGEX"
        | "DENYLIST"
        | "GRAVITY_CNAME"
        | "REGEX_CNAME"
        | "DENYLIST_CNAME"
        | "EXTERNAL_BLOCKED_IP"
        | "EXTERNAL_BLOCKED_NULL"
        | "EXTERNAL_BLOCKED_NXRA"
        | "EXTERNAL_BLOCKED_EDE15" => Some("blocked"),
        "FORWARDED" | "RETRIED" | "RETRIED_DNSSEC" => Some("upstream"),
        "CACHE" | "CACHE_STALE" => Some("cache"),

        "blocked" => Some("blocked"),
        "allowed" => Some("allowed"),
        "cache" | "cached" => Some("cache"),
        _ => None,
    }
}

/// Pi-hole v6 GET /api/queries
pub async fn get_queries(
    State(state): State<PiholeAppState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueriesResponse>, PiholeApiError> {
    let limit = params.length.unwrap_or(DEFAULT_LIMIT);
    let offset = params.start.unwrap_or(0);

    let category = params.status.as_deref().and_then(pihole_status_to_category);

    let input = ferrous_dns_application::use_cases::PagedQueryInput {
        limit,
        offset,
        period_hours: STATS_PERIOD_HOURS,
        cursor: params.cursor,
        domain: params.domain.as_deref(),
        category,
        client_ip: params.client.as_deref(),
        ..Default::default()
    };

    let result = state.query.get_recent_queries.execute_paged(&input).await?;

    let queries: Vec<PiholeQueryEntry> = result
        .queries
        .into_iter()
        .map(|q| PiholeQueryEntry {
            id: q.id.unwrap_or(0),
            time: q
                .timestamp
                .as_deref()
                .and_then(parse_unix_epoch)
                .map(|ts| ts as f64)
                .unwrap_or(0.0),
            r#type: q.record_type.to_string(),
            domain: q.domain.to_string(),
            client: PiholeClientRef {
                ip: q.client_ip.to_string(),
                name: q
                    .client_hostname
                    .as_ref()
                    .map(|h| h.to_string())
                    .filter(|h| !h.is_empty()),
            },
            status: map_query_status(q.blocked, q.cache_hit, q.block_source.as_ref()),
            dnssec: q.dnssec_status.unwrap_or("UNKNOWN").to_string(),
            reply: PiholeReply {
                r#type: q
                    .response_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                time: q.response_time_us.map(|t| t as f64 / 1000.0).unwrap_or(0.0),
            },
            upstream: q
                .upstream_server
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            cname: None,
            list_id: None,
            ede: PiholeEde {
                code: -1,
                text: None,
            },
        })
        .collect();

    Ok(Json(QueriesResponse {
        records_total: result.records_total,
        records_filtered: result.records_filtered,
        cursor: result.next_cursor,
        queries,
        draw: params.draw,
    }))
}

/// Pi-hole v6 GET /api/queries/suggestions
///
/// Returns categorised suggestions based on recent queries.
///
// TODO: extract aggregation into a dedicated use case (GetQuerySuggestionsUseCase)
// with DISTINCT SQL queries instead of in-memory dedup
pub async fn get_suggestions(
    State(state): State<PiholeAppState>,
) -> Result<Json<SuggestionsResponse>, PiholeApiError> {
    let logs = state
        .query
        .get_recent_queries
        .execute(SUGGESTIONS_QUERY_LIMIT, STATS_PERIOD_HOURS)
        .await?;

    let (mut domains, mut ips, mut names, mut upstreams) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    let (mut types, mut statuses, mut replies, mut dnssecs) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );

    for q in &logs {
        domains.insert(q.domain.to_string());
        ips.insert(q.client_ip.to_string());
        if let Some(ref h) = q.client_hostname {
            if !h.is_empty() {
                names.insert(h.to_string());
            }
        }
        if let Some(ref u) = q.upstream_server {
            upstreams.insert(u.to_string());
        }
        types.insert(q.record_type.to_string());
        statuses
            .insert(map_query_status(q.blocked, q.cache_hit, q.block_source.as_ref()).to_string());
        if let Some(r) = q.response_status {
            replies.insert(r.to_string());
        }
        if let Some(d) = q.dnssec_status {
            dnssecs.insert(d.to_string());
        }
    }

    let truncate = |s: BTreeSet<String>| -> Vec<String> {
        s.into_iter().take(MAX_SUGGESTIONS_PER_CATEGORY).collect()
    };

    Ok(Json(SuggestionsResponse {
        domain: truncate(domains),
        client_ip: truncate(ips),
        client_name: truncate(names),
        upstream: truncate(upstreams),
        r#type: truncate(types),
        status: truncate(statuses),
        reply: truncate(replies),
        dnssec: truncate(dnssecs),
    }))
}
