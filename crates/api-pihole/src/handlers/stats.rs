use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use chrono::{NaiveDateTime, Utc};
use ferrous_dns_application::ports::TimeGranularity;
use ferrous_dns_application::use_cases::PagedQueryInput;
use ferrous_dns_domain::{DnsProtocol, DomainError, QueryStats};
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    crud::unix_seconds,
    dto::queries::{blocked_status, upstream_port},
    dto::stats::{
        ClientSummary, DatabaseSummaryResponse, DatabaseTopClientEntry, DatabaseTopClientsResponse,
        GravitySummary, HistoryBucket, HistoryResponse, QueryStatusCounts, QuerySummary,
        QueryTypeCounts, QueryTypesResponse, RecentBlockedResponse, ReplyTypeCounts,
        SummaryResponse, TopClientEntry, TopClientsResponse, TopDomainEntry, TopDomainsResponse,
    },
    dto::upstreams::{UpstreamEntry, UpstreamStatistics, UpstreamsResponse},
    errors::{pihole_error_response, PiholeApiError},
    state::PiholeAppState,
};

pub const STATS_PERIOD_HOURS: f32 = 24.0;

/// FTL's default for the `count` of `/stats/top_domains` and `/stats/top_clients`.
const DEFAULT_TOP_COUNT: u32 = 10;

/// FTL's default for the `count` of `/stats/recent_blocked`.
const DEFAULT_RECENT_BLOCKED_COUNT: u32 = 1;

/// Longest `from` window honoured: past any retention, and small enough that
/// the repository's hours-to-timestamp arithmetic cannot overflow.
pub(crate) const MAX_PERIOD_HOURS: f32 = 24.0 * 366.0 * 10.0;

/// Width of a `/history` bucket, FTL's `OVERTIME_INTERVAL`.
pub(crate) const HISTORY_BUCKET_SECS: i64 = 600;

/// Buckets in `/history` and `/history/clients`: 24 hours plus the current
/// one. Glance pihole-v6 expects exactly this many.
const HISTORY_BUCKETS: i64 = 145;

/// Query parameters of the live `/stats/*` endpoints.
#[derive(Debug, Deserialize)]
pub struct StatsQueryParams {
    /// Ferrous extension: the window in hours back from now (default 24).
    pub(crate) from: Option<f32>,
    /// FTL's name for the number of entries to return.
    pub(crate) count: Option<u32>,
    /// Ferrous's earlier name for `count`, still honoured.
    pub(crate) limit: Option<u32>,
    pub(crate) blocked: Option<bool>,
}

impl StatsQueryParams {
    pub(crate) fn period(&self) -> f32 {
        match self.from {
            Some(hours) if hours.is_finite() => hours.clamp(0.0, MAX_PERIOD_HOURS),
            _ => STATS_PERIOD_HOURS,
        }
    }

    pub(crate) fn limit(&self) -> u32 {
        self.count.or(self.limit).unwrap_or(DEFAULT_TOP_COUNT)
    }
}

/// Query parameters of `/stats/database/*`: FTL's window as Unix timestamps.
#[derive(Debug, Deserialize)]
pub struct DatabaseQueryParams {
    from: Option<f64>,
    until: Option<f64>,
    count: Option<u32>,
    blocked: Option<bool>,
}

impl DatabaseQueryParams {
    /// Hours from `from` until now. `until` is required as in FTL, but read
    /// as now: the query-log stores only answer windows that end now.
    fn period(&self) -> Result<f32, DatabaseStatsError> {
        // stats_database.c rejects a missing or sub-1 timestamp alike.
        let valid = |timestamp: Option<f64>| timestamp.filter(|t| *t >= 1.0);
        let (Some(from), Some(_until)) = (valid(self.from), valid(self.until)) else {
            return Err(DatabaseStatsError::MissingWindow);
        };
        let hours = (Utc::now().timestamp() as f64 - from) / 3_600.0;
        Ok((hours as f32).clamp(0.0, MAX_PERIOD_HOURS))
    }

    fn limit(&self) -> u32 {
        self.count.unwrap_or(DEFAULT_TOP_COUNT)
    }
}

/// A failed `/stats/database/*` request.
pub enum DatabaseStatsError {
    /// `from` or `until` is missing, answered as stats_database.c does.
    MissingWindow,
    Domain(DomainError),
}

impl From<DomainError> for DatabaseStatsError {
    fn from(err: DomainError) -> Self {
        Self::Domain(err)
    }
}

impl IntoResponse for DatabaseStatsError {
    fn into_response(self) -> Response {
        match self {
            Self::MissingWindow => pihole_error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "You need to specify both \"from\" and \"until\" in the request.",
                None,
            ),
            Self::Domain(err) => PiholeApiError(err).into_response(),
        }
    }
}

/// Pi-hole v6 GET /api/stats/summary
#[utoipa::path(
    get,
    path = "/stats/summary",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours (default 24)")
    ),
    responses(
        (status = 200, description = "Summary statistics", body = SummaryResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_summary(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<SummaryResponse>, PiholeApiError> {
    Ok(Json(summary(&state, params.period()).await?))
}

/// The `/stats/summary` reply over the last `period` hours; `/padd` reuses it.
pub(crate) async fn summary(
    state: &PiholeAppState,
    period: f32,
) -> Result<SummaryResponse, DomainError> {
    let (stats, blocklists, allowlists, clients) = tokio::try_join!(
        state.query.get_stats.execute(period),
        state.lists.get_blocklist_sources.get_all(),
        state.lists.get_whitelist_sources.get_all(),
        state.clients.get_clients.get_stats(),
    )?;

    let total = stats.queries_total;
    let blocked = stats.queries_blocked;
    let percent_blocked = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let cache_hits = stats.source_stats.get("cache").copied().unwrap_or(0);
    let local_dns = stats.source_stats.get("local_dns").copied().unwrap_or(0);
    // Only upstream answers are forwarded; local records and failures are not.
    let forwarded = forwarded_count(&stats.source_stats);

    let mut types = QueryTypeCounts::default();
    for (record_type, count) in &stats.queries_by_type {
        types.add(record_type.as_str(), *count);
    }

    let mut status = QueryStatusCounts::default();
    for (source, count) in &stats.source_stats {
        let name = match source.as_str() {
            // FTL counts answers from local configuration as cached.
            "cache" | "local_dns" => "CACHE",
            upstream if is_upstream_key(upstream) => "FORWARDED",
            block_source => blocked_status(block_source.parse().ok()),
        };
        status.add(name, *count);
    }

    let domains_being_blocked = state.blocking.block_filter_engine.compiled_domain_count() as u64;
    // FTL reports when gravity last ran. Each list is stamped when it is
    // downloaded, so the newest stamp is the last run that fetched one.
    let last_update = blocklists
        .iter()
        .map(|list| list.last_synced_at.as_deref())
        .chain(allowlists.iter().map(|list| list.last_synced_at.as_deref()))
        .map(unix_seconds)
        .max()
        .unwrap_or(0);

    Ok(SummaryResponse {
        queries: QuerySummary {
            total,
            blocked,
            percent_blocked,
            unique_domains: 0,
            forwarded,
            cached: cache_hits + local_dns,
            frequency: 0.0,
            types,
            status,
            replies: ReplyTypeCounts::default(),
        },
        clients: ClientSummary {
            active: stats.unique_clients,
            total: clients.total_clients,
        },
        gravity: GravitySummary {
            domains_being_blocked,
            last_update,
        },
    })
}

/// Start of every `/history` bucket, oldest first, ending with the current
/// one, and the window in hours from the oldest start until now.
pub(crate) fn history_buckets() -> (Vec<i64>, f32) {
    let now = Utc::now().timestamp();
    let newest = now - now.rem_euclid(HISTORY_BUCKET_SECS);
    let oldest = newest - (HISTORY_BUCKETS - 1) * HISTORY_BUCKET_SECS;
    let starts = (0..HISTORY_BUCKETS)
        .map(|i| oldest + i * HISTORY_BUCKET_SECS)
        .collect();
    (starts, (now - oldest) as f32 / 3_600.0)
}

/// FTL stamps each bucket at its centre (overTime.c).
pub(crate) fn bucket_centre(start: i64) -> i64 {
    start + HISTORY_BUCKET_SECS / 2
}

/// Pi-hole v6 GET /api/history, also served at /api/stats/history
///
/// Always 145 buckets of 10 minutes; buckets with no queries are zero.
#[utoipa::path(
    get,
    path = "/history",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours to read (default: the 145 buckets)")
    ),
    responses(
        (status = 200, description = "Time-series history of queries", body = HistoryResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_history(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<HistoryResponse>, PiholeApiError> {
    let (starts, window_hours) = history_buckets();
    let period_hours = params.from.unwrap_or(window_hours);
    let buckets = state
        .query
        .get_timeline
        .execute(period_hours, TimeGranularity::TenMinutes)
        .await?;

    let by_start: HashMap<i64, _> = buckets
        .into_iter()
        .filter_map(|b| {
            let start = NaiveDateTime::parse_from_str(&b.timestamp, "%Y-%m-%d %H:%M:%S").ok()?;
            Some((start.and_utc().timestamp(), b))
        })
        .collect();

    let history = starts
        .into_iter()
        .map(|start| {
            let bucket = by_start.get(&start);
            HistoryBucket {
                timestamp: bucket_centre(start),
                total: bucket.map_or(0, |b| b.total),
                cached: bucket.map_or(0, |b| b.cached),
                blocked: bucket.map_or(0, |b| b.blocked),
                forwarded: bucket.map_or(0, |b| b.forwarded),
            }
        })
        .collect();

    Ok(Json(HistoryResponse { history }))
}

/// Pi-hole v6 GET /api/stats/top_blocked
#[utoipa::path(
    get,
    path = "/stats/top_blocked",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours"),
        ("count" = Option<u32>, Query, description = "Max items (default 10)")
    ),
    responses(
        (status = 200, description = "Top blocked domains", body = TopDomainsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_top_blocked(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<TopDomainsResponse>, PiholeApiError> {
    Ok(Json(
        top_domains(&state, params.period(), params.limit(), true).await?,
    ))
}

pub(crate) async fn top_domains(
    state: &PiholeAppState,
    period: f32,
    limit: u32,
    blocked: bool,
) -> Result<TopDomainsResponse, DomainError> {
    let (domain_list, stats) = tokio::join!(
        async {
            if blocked {
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

    Ok(TopDomainsResponse {
        domains,
        total_queries: stats.queries_total,
        blocked_queries: stats.queries_blocked,
    })
}

/// Pi-hole v6 GET /api/stats/top_clients
///
/// Ranks clients by all their queries, or by blocked queries with `?blocked=true`.
#[utoipa::path(
    get,
    path = "/stats/top_clients",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours"),
        ("count" = Option<u32>, Query, description = "Max items (default 10)"),
        ("blocked" = Option<bool>, Query, description = "Rank by blocked queries")
    ),
    responses(
        (status = 200, description = "Top clients", body = TopClientsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_top_clients(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<TopClientsResponse>, PiholeApiError> {
    let ranked = top_clients(
        &state,
        params.period(),
        params.limit(),
        params.blocked.unwrap_or(false),
    )
    .await?;

    Ok(Json(TopClientsResponse {
        clients: ranked
            .clients
            .into_iter()
            .map(|(ip, hostname, count)| TopClientEntry {
                ip,
                name: hostname.unwrap_or_default(),
                count,
            })
            .collect(),
        total_queries: ranked.total_queries,
        blocked_queries: ranked.blocked_queries,
    }))
}

pub(crate) struct RankedClients {
    /// `(ip, hostname, count)`, highest count first.
    pub(crate) clients: Vec<(String, Option<String>, u64)>,
    pub(crate) total_queries: u64,
    pub(crate) blocked_queries: u64,
}

/// Clients by all their queries, or by blocked queries when `blocked`.
pub(crate) async fn top_clients(
    state: &PiholeAppState,
    period: f32,
    limit: u32,
    blocked: bool,
) -> Result<RankedClients, DomainError> {
    let (clients, stats) = tokio::join!(
        async {
            if blocked {
                state
                    .query
                    .get_top_blocked_clients
                    .execute(limit, period)
                    .await
            } else {
                state.query.get_top_clients.execute(limit, period).await
            }
        },
        state.query.get_stats.execute(period),
    );
    let stats = stats?;

    Ok(RankedClients {
        clients: clients?,
        total_queries: stats.queries_total,
        blocked_queries: stats.queries_blocked,
    })
}

/// Pi-hole v6 GET /api/stats/query_types
#[utoipa::path(
    get,
    path = "/stats/query_types",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours")
    ),
    responses(
        (status = 200, description = "Query type distribution", body = QueryTypesResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_query_types(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<QueryTypesResponse>, PiholeApiError> {
    Ok(Json(query_types(&state, params.period()).await?))
}

async fn query_types(
    state: &PiholeAppState,
    period: f32,
) -> Result<QueryTypesResponse, DomainError> {
    let stats = state.query.get_stats.execute(period).await?;
    let mut types = QueryTypeCounts::default();
    for (record_type, count) in &stats.queries_by_type {
        types.add(record_type.as_str(), *count);
    }
    Ok(QueryTypesResponse { types })
}

/// Pi-hole v6 GET /api/stats/top_domains
///
/// Returns top allowed domains by default, or top blocked domains when `?blocked=true`.
#[utoipa::path(
    get,
    path = "/stats/top_domains",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours"),
        ("count" = Option<u32>, Query, description = "Max items (default 10)"),
        ("blocked" = Option<bool>, Query, description = "Return top blocked instead of top allowed")
    ),
    responses(
        (status = 200, description = "Top domains", body = TopDomainsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_top_domains(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<TopDomainsResponse>, PiholeApiError> {
    let blocked = params.blocked.unwrap_or(false);
    Ok(Json(
        top_domains(&state, params.period(), params.limit(), blocked).await?,
    ))
}

/// Pi-hole v6 GET /api/stats/upstreams
///
/// Returns where answers came from: the `blocklist` and `cache` pseudo-entries,
/// then each upstream server (merged across pools) by descending count.
#[utoipa::path(
    get,
    path = "/stats/upstreams",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours")
    ),
    responses(
        (status = 200, description = "Upstream usage statistics", body = UpstreamsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_upstreams(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<UpstreamsResponse>, PiholeApiError> {
    Ok(Json(upstreams(&state, params.period()).await?))
}

async fn upstreams(state: &PiholeAppState, period: f32) -> Result<UpstreamsResponse, DomainError> {
    let stats = state.query.get_stats.execute(period).await?;
    let servers = upstream_servers(&stats);
    let forwarded_queries: u64 = servers.iter().map(|(_, count)| count).sum();

    let cached = ["cache", "local_dns"]
        .iter()
        .filter_map(|key| stats.source_stats.get(*key))
        .sum();
    let mut upstreams = vec![
        pseudo_upstream("blocklist", stats.queries_blocked),
        pseudo_upstream("cache", cached),
    ];
    upstreams.extend(
        servers
            .into_iter()
            .map(|(server, count)| upstream_entry(server, count)),
    );

    Ok(UpstreamsResponse {
        upstreams,
        forwarded_queries,
        total_queries: stats.queries_total,
    })
}

/// Each upstream server that answered in `stats`, with its queries merged
/// across pools, by descending count.
pub(crate) fn upstream_servers(stats: &QueryStats) -> Vec<(&str, u64)> {
    let mut per_server: HashMap<&str, u64> = HashMap::new();
    for (key, count) in &stats.source_stats {
        // Upstream keys are `{pool}:{server}`; the other keys have no colon.
        if let Some((_pool, server)) = key.split_once(':') {
            *per_server.entry(server).or_default() += count;
        }
    }
    let mut servers: Vec<(&str, u64)> = per_server.into_iter().collect();
    servers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    servers
}

fn pseudo_upstream(name: &str, count: u64) -> UpstreamEntry {
    UpstreamEntry {
        ip: Some(name.to_string()),
        name: Some(name.to_string()),
        port: -1,
        count,
        statistics: UpstreamStatistics::default(),
    }
}

/// An upstream as FTL lists it, from the server URL the query log records
/// (e.g. `udp://1.1.1.1:53`). A server that no longer parses keeps its text
/// as the name, with port -1.
fn upstream_entry(server: &str, count: u64) -> UpstreamEntry {
    let Ok(protocol) = server.parse::<DnsProtocol>() else {
        return UpstreamEntry {
            ip: None,
            name: Some(server.to_string()),
            port: -1,
            count,
            statistics: UpstreamStatistics::default(),
        };
    };
    UpstreamEntry {
        ip: protocol.socket_addr().map(|addr| addr.ip().to_string()),
        name: protocol.hostname().map(str::to_owned),
        port: i32::from(upstream_port(&protocol)),
        count,
        statistics: UpstreamStatistics::default(),
    }
}

/// Pi-hole v6 GET /api/stats/recent_blocked
///
/// Returns the most recently blocked domains, newest first, one per query.
#[utoipa::path(
    get,
    path = "/stats/recent_blocked",
    tag = "pihole:stats",
    params(
        ("count" = Option<u32>, Query, description = "Number of domains (default 1)")
    ),
    responses(
        (status = 200, description = "Most recently blocked domains", body = RecentBlockedResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_recent_blocked(
    State(state): State<PiholeAppState>,
    Query(params): Query<StatsQueryParams>,
) -> Result<Json<RecentBlockedResponse>, PiholeApiError> {
    let count = params.count.unwrap_or(DEFAULT_RECENT_BLOCKED_COUNT);
    Ok(Json(RecentBlockedResponse {
        blocked: recent_blocked(&state, count).await?,
    }))
}

/// The `count` most recently blocked domains, newest first, at least one.
pub(crate) async fn recent_blocked(
    state: &PiholeAppState,
    count: u32,
) -> Result<Vec<String>, DomainError> {
    let input = PagedQueryInput {
        limit: count.max(1),
        period_hours: STATS_PERIOD_HOURS,
        category: Some("blocked"),
        ..Default::default()
    };
    let page = state.query.get_recent_queries.execute_paged(&input).await?;

    Ok(page
        .queries
        .into_iter()
        .map(|q| q.domain.to_string())
        .collect())
}

/// `source_stats` keys upstreams as `"{pool}:{server}"`; the other keys
/// (`cache`, `local_dns`, block sources) never contain a colon.
fn is_upstream_key(key: &str) -> bool {
    key.contains(':')
}

fn forwarded_count(source_stats: &HashMap<String, u64>) -> u64 {
    source_stats
        .iter()
        .filter(|(key, _)| is_upstream_key(key))
        .map(|(_, count)| count)
        .sum()
}

/// Pi-hole v6 GET /api/stats/database/summary
#[utoipa::path(
    get,
    path = "/stats/database/summary",
    tag = "pihole:stats",
    params(
        ("from" = f64, Query, description = "Window start, Unix timestamp"),
        ("until" = f64, Query, description = "Window end, Unix timestamp; read as now")
    ),
    responses(
        (status = 200, description = "Long-term summary", body = DatabaseSummaryResponse),
        (status = 400, description = "`from` or `until` missing")
    ),
    security(("session_id" = []))
)]
pub async fn get_database_summary(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<DatabaseSummaryResponse>, DatabaseStatsError> {
    let period = params.period()?;
    let stats = state.query.get_stats.execute(period).await?;

    let sum_queries = stats.queries_total;
    let sum_blocked = stats.queries_blocked;
    let percent_blocked = if sum_queries > 0 {
        (sum_blocked as f64 / sum_queries as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(DatabaseSummaryResponse {
        sum_queries,
        sum_blocked,
        percent_blocked,
        total_clients: stats.unique_clients,
    }))
}

/// Pi-hole v6 GET /api/stats/database/top_domains
#[utoipa::path(
    get,
    path = "/stats/database/top_domains",
    tag = "pihole:stats",
    params(
        ("from" = f64, Query, description = "Window start, Unix timestamp"),
        ("until" = f64, Query, description = "Window end, Unix timestamp; read as now"),
        ("count" = Option<u32>, Query, description = "Max items (default 10)"),
        ("blocked" = Option<bool>, Query, description = "Return top blocked instead of top allowed")
    ),
    responses(
        (status = 200, description = "Long-term top domains", body = TopDomainsResponse),
        (status = 400, description = "`from` or `until` missing")
    ),
    security(("session_id" = []))
)]
pub async fn get_database_top_domains(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopDomainsResponse>, DatabaseStatsError> {
    let period = params.period()?;
    let blocked = params.blocked.unwrap_or(false);
    Ok(Json(
        top_domains(&state, period, params.limit(), blocked).await?,
    ))
}

/// Pi-hole v6 GET /api/stats/database/top_clients
#[utoipa::path(
    get,
    path = "/stats/database/top_clients",
    tag = "pihole:stats",
    params(
        ("from" = f64, Query, description = "Window start, Unix timestamp"),
        ("until" = f64, Query, description = "Window end, Unix timestamp; read as now"),
        ("count" = Option<u32>, Query, description = "Max items (default 10)"),
        ("blocked" = Option<bool>, Query, description = "Rank by blocked queries")
    ),
    responses(
        (status = 200, description = "Long-term top clients", body = DatabaseTopClientsResponse),
        (status = 400, description = "`from` or `until` missing")
    ),
    security(("session_id" = []))
)]
pub async fn get_database_top_clients(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<DatabaseTopClientsResponse>, DatabaseStatsError> {
    let period = params.period()?;
    let blocked = params.blocked.unwrap_or(false);
    let ranked = top_clients(&state, period, params.limit(), blocked).await?;

    Ok(Json(DatabaseTopClientsResponse {
        clients: ranked
            .clients
            .into_iter()
            .map(|(ip, hostname, count)| DatabaseTopClientEntry {
                ip,
                name: hostname.filter(|name| !name.is_empty()),
                count,
            })
            .collect(),
        total_queries: ranked.total_queries,
        blocked_queries: ranked.blocked_queries,
    }))
}

/// Pi-hole v6 GET /api/stats/database/upstreams
#[utoipa::path(
    get,
    path = "/stats/database/upstreams",
    tag = "pihole:stats",
    params(
        ("from" = f64, Query, description = "Window start, Unix timestamp"),
        ("until" = f64, Query, description = "Window end, Unix timestamp; read as now")
    ),
    responses(
        (status = 200, description = "Long-term upstream usage", body = UpstreamsResponse),
        (status = 400, description = "`from` or `until` missing")
    ),
    security(("session_id" = []))
)]
pub async fn get_database_upstreams(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<UpstreamsResponse>, DatabaseStatsError> {
    let period = params.period()?;
    Ok(Json(upstreams(&state, period).await?))
}

/// Pi-hole v6 GET /api/stats/database/query_types
#[utoipa::path(
    get,
    path = "/stats/database/query_types",
    tag = "pihole:stats",
    params(
        ("from" = f64, Query, description = "Window start, Unix timestamp"),
        ("until" = f64, Query, description = "Window end, Unix timestamp; read as now")
    ),
    responses(
        (status = 200, description = "Long-term query type counts", body = QueryTypesResponse),
        (status = 400, description = "`from` or `until` missing")
    ),
    security(("session_id" = []))
)]
pub async fn get_database_query_types(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<QueryTypesResponse>, DatabaseStatsError> {
    let period = params.period()?;
    Ok(Json(query_types(&state, period).await?))
}
