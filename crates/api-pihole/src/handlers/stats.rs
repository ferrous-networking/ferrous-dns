use axum::extract::{Query, State};
use axum::Json;
use ferrous_dns_application::ports::TimeGranularity;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    dto::stats::{
        ClientSummary, GravitySummary, HistoryBucket, HistoryResponse, QuerySummary,
        QueryTypesResponse, RecentBlockedResponse, SummaryResponse, TopClientEntry,
        TopClientsResponse, TopDomainEntry, TopDomainsResponse,
    },
    dto::upstreams::UpstreamsResponse,
    errors::PiholeApiError,
    state::PiholeAppState,
    timestamp::parse_unix_epoch,
};

pub const STATS_PERIOD_HOURS: f32 = 24.0;
pub const TOP_ITEMS_LIMIT: u32 = 25;

const RECENT_BLOCKED_SCAN_LIMIT: u32 = 200;

/// Known internal source_stats keys that are not upstream servers.
const INTERNAL_SOURCE_KEYS: &[&str] = &["cache", "local_dns", "blocked", "safe_search"];

/// Query parameters for database endpoints (`/stats/database/*`).
#[derive(Debug, Deserialize)]
pub struct DatabaseQueryParams {
    pub(crate) from: Option<f32>,
    pub(crate) limit: Option<u32>,
    pub(crate) blocked: Option<bool>,
}

impl DatabaseQueryParams {
    pub(crate) fn period(&self) -> f32 {
        self.from.unwrap_or(STATS_PERIOD_HOURS)
    }

    pub(crate) fn limit(&self) -> u32 {
        self.limit.unwrap_or(TOP_ITEMS_LIMIT)
    }
}

/// Pi-hole v6 GET /api/stats/summary
pub async fn get_summary(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<SummaryResponse>, PiholeApiError> {
    let period = params.period();
    let stats = state.query.get_stats.execute(period).await?;

    let total = stats.queries_total;
    let blocked = stats.queries_blocked;
    let percent_blocked = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let cache_hits = stats.source_stats.get("cache").copied().unwrap_or(0);
    let forwarded = total.saturating_sub(blocked).saturating_sub(cache_hits);

    let query_types: HashMap<String, u64> = stats
        .queries_by_type
        .into_iter()
        .map(|(record_type, count)| (record_type.to_string(), count))
        .collect();

    let domains_being_blocked = state.blocking.block_filter_engine.compiled_domain_count() as u64;

    let response = SummaryResponse {
        queries: QuerySummary {
            total,
            blocked,
            percent_blocked,
            // TODO: implement unique domain count via dedicated query
            unique_domains: 0,
            forwarded,
            cached: cache_hits,
            // TODO: compute queries-per-second from uptime + total
            frequency: 0.0,
            types: query_types,
        },
        clients: ClientSummary {
            active: stats.unique_clients,
            // TODO: distinguish total (all-time) from active (period) clients
            total: stats.unique_clients,
        },
        gravity: GravitySummary {
            domains_being_blocked,
            // TODO: populate from blocklist last-sync timestamp
            last_update: 0,
        },
        status: if state.blocking.block_filter_engine.is_blocking_enabled() {
            "enabled"
        } else {
            "disabled"
        },
    };

    Ok(Json(response))
}

/// Pi-hole v6 GET /api/stats/history
pub async fn get_history(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<HistoryResponse>, PiholeApiError> {
    let buckets = state
        .query
        .get_timeline
        .execute(params.period() as u32, TimeGranularity::QuarterHour)
        .await?;

    let history: Vec<HistoryBucket> = buckets
        .into_iter()
        .filter_map(|b| {
            let ts = parse_unix_epoch(&b.timestamp)?;
            Some(HistoryBucket {
                timestamp: ts,
                total: b.total,
                blocked: b.blocked,
                // TODO: TimelineBucket does not break down cache vs forwarded yet
                cached: 0,
                forwarded: b.unblocked,
            })
        })
        .collect();

    Ok(Json(HistoryResponse { history }))
}

/// Pi-hole v6 GET /api/stats/top_blocked
pub async fn get_top_blocked(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopDomainsResponse>, PiholeApiError> {
    let period = params.period();
    let limit = params.limit();

    let (domains_raw, stats) = tokio::join!(
        state.query.get_top_blocked_domains.execute(limit, period),
        state.query.get_stats.execute(period),
    );

    let domains = domains_raw?
        .into_iter()
        .map(|(domain, count)| TopDomainEntry { domain, count })
        .collect();
    let stats = stats?;

    Ok(Json(TopDomainsResponse {
        domains,
        total_queries: stats.queries_total,
        blocked_queries: stats.queries_blocked,
    }))
}

/// Pi-hole v6 GET /api/stats/top_clients
pub async fn get_top_clients(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopClientsResponse>, PiholeApiError> {
    let period = params.period();
    let limit = params.limit();

    let (clients_raw, stats) = tokio::join!(
        state.query.get_top_clients.execute(limit, period),
        state.query.get_stats.execute(period),
    );

    let clients = clients_raw?
        .into_iter()
        .map(|(ip, hostname, count)| TopClientEntry {
            ip,
            name: hostname.unwrap_or_default(),
            count,
        })
        .collect();
    let stats = stats?;

    Ok(Json(TopClientsResponse {
        clients,
        total_queries: stats.queries_total,
        blocked_queries: stats.queries_blocked,
    }))
}

/// Pi-hole v6 GET /api/stats/query_types
pub async fn get_query_types(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<QueryTypesResponse>, PiholeApiError> {
    let period = params.period();
    let stats = state.query.get_stats.execute(period).await?;

    let total: u64 = stats.queries_by_type.values().sum();

    let querytypes: HashMap<String, f64> = stats
        .queries_by_type
        .into_iter()
        .map(|(record_type, count)| {
            let pct = if total > 0 {
                (count as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            (record_type.to_string(), pct)
        })
        .collect();

    Ok(Json(QueryTypesResponse { querytypes }))
}

/// Pi-hole v6 GET /api/stats/top_domains
///
/// Returns top allowed domains by default, or top blocked domains when `?blocked=true`.
pub async fn get_top_domains(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopDomainsResponse>, PiholeApiError> {
    let period = params.period();
    let limit = params.limit();
    let is_blocked = params.blocked.unwrap_or(false);

    let (domain_list, stats) = tokio::join!(
        async {
            if is_blocked {
                state
                    .query
                    .get_top_blocked_domains
                    .execute(limit, period)
                    .await
            } else {
                state
                    .query
                    .get_top_allowed_domains
                    .execute(limit, period)
                    .await
            }
        },
        state.query.get_stats.execute(period),
    );

    let domains = domain_list?
        .into_iter()
        .map(|(domain, count)| TopDomainEntry { domain, count })
        .collect();
    let stats = stats?;

    Ok(Json(TopDomainsResponse {
        domains,
        total_queries: stats.queries_total,
        blocked_queries: stats.queries_blocked,
    }))
}

/// Pi-hole v6 GET /api/stats/upstreams
///
/// Returns upstream DNS server usage statistics.
/// Upstream keys are identified by exclusion of known internal source names.
pub async fn get_upstreams(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<UpstreamsResponse>, PiholeApiError> {
    let stats = state.query.get_stats.execute(params.period()).await?;

    let upstreams: HashMap<String, u64> = stats
        .source_stats
        .iter()
        .filter(|(key, _)| !INTERNAL_SOURCE_KEYS.contains(&key.as_str()))
        .map(|(key, count)| (key.clone(), *count))
        .collect();

    let forwarded_queries: u64 = upstreams.values().sum();

    Ok(Json(UpstreamsResponse {
        upstreams,
        forwarded_queries,
        total_queries: stats.queries_total,
    }))
}

/// Pi-hole v6 GET /api/stats/recent_blocked
///
/// Returns the most recently blocked domain.
// TODO: replace with a dedicated use case (GetMostRecentBlockedUseCase)
// using `WHERE blocked = 1 ORDER BY timestamp DESC LIMIT 1` in the repository
pub async fn get_recent_blocked(
    State(state): State<PiholeAppState>,
) -> Result<Json<RecentBlockedResponse>, PiholeApiError> {
    let queries = state
        .query
        .get_recent_queries
        .execute(RECENT_BLOCKED_SCAN_LIMIT, STATS_PERIOD_HOURS)
        .await?;

    let domain = queries
        .into_iter()
        .find(|q| q.blocked)
        .map(|q| q.domain.to_string());

    Ok(Json(RecentBlockedResponse { domain }))
}
