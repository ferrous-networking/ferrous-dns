use axum::extract::{Query, State};
use axum::Json;
use chrono::{Timelike, Utc};
use ferrous_dns_application::ports::TimeGranularity;
use ferrous_dns_domain::{DnsProtocol, DomainError};
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    dto::queries::blocked_status,
    dto::stats::{
        ClientSummary, GravitySummary, HistoryBucket, HistoryResponse, QueryStatusCounts,
        QuerySummary, QueryTypeCounts, QueryTypesResponse, RecentBlockedResponse, ReplyTypeCounts,
        SummaryResponse, TopClientEntry, TopClientsResponse, TopDomainEntry, TopDomainsResponse,
    },
    dto::upstreams::{UpstreamEntry, UpstreamStatistics, UpstreamsResponse},
    errors::PiholeApiError,
    state::PiholeAppState,
};

pub const STATS_PERIOD_HOURS: f32 = 24.0;
pub const TOP_ITEMS_LIMIT: u32 = 25;

/// FTL's default for the `count` of `/stats/top_domains` and `/stats/top_clients`.
const DEFAULT_TOP_COUNT: u32 = 10;

const RECENT_BLOCKED_SCAN_LIMIT: u32 = 200;

/// Longest `from` window honoured: past any retention, and small enough that
/// the repository's hours-to-timestamp arithmetic cannot overflow.
const MAX_PERIOD_HOURS: f32 = 24.0 * 366.0 * 10.0;

/// Query parameters for database endpoints (`/stats/database/*`).
#[derive(Debug, Deserialize)]
pub struct DatabaseQueryParams {
    pub(crate) from: Option<f32>,
    /// FTL's name for the number of entries to return.
    pub(crate) count: Option<u32>,
    /// Ferrous's earlier name for `count`, still honoured.
    pub(crate) limit: Option<u32>,
    pub(crate) blocked: Option<bool>,
}

impl DatabaseQueryParams {
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

    let response = SummaryResponse {
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
            total: stats.unique_clients,
        },
        gravity: GravitySummary {
            domains_being_blocked,
            last_update: 0,
        },
    };

    Ok(Json(response))
}

/// Pi-hole v6 GET /api/stats/history and GET /api/history
///
/// Glance pihole-v6 expects exactly 145 buckets of 10-minute intervals (24h + 1).
/// Buckets with no queries are padded with zeros to guarantee the exact count.
#[utoipa::path(
    get,
    path = "/stats/history",
    tag = "pihole:stats",
    params(
        ("from" = Option<f32>, Query, description = "Period in hours (default 25)")
    ),
    responses(
        (status = 200, description = "Time-series history of queries", body = HistoryResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_history(
    State(state): State<PiholeAppState>,
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<HistoryResponse>, PiholeApiError> {
    const BUCKET_COUNT: usize = 145;
    const BUCKET_MINUTES: i64 = 10;

    // Fetch slightly more than 24h to cover all 145 buckets regardless of alignment.
    let period_hours = params.from.unwrap_or(25.0);
    let buckets = state
        .query
        .get_timeline
        .execute(period_hours, TimeGranularity::TenMinutes)
        .await?;

    // Build lookup: "YYYY-MM-DD HH:MM:00" → (total, blocked, unblocked)
    let bucket_map: HashMap<String, (u64, u64, u64)> = buckets
        .into_iter()
        .map(|b| (b.timestamp, (b.total, b.blocked, b.unblocked)))
        .collect();

    // The newest bucket starts at the current 10-minute boundary.
    let now = Utc::now();
    let current_minute = (now.minute() / BUCKET_MINUTES as u32) * BUCKET_MINUTES as u32;
    let grid_end = now
        .with_minute(current_minute)
        .unwrap_or(now)
        .with_second(0)
        .unwrap_or(now)
        .with_nanosecond(0)
        .unwrap_or(now);

    let history: Vec<HistoryBucket> = (0..BUCKET_COUNT)
        .map(|i| {
            let offset_minutes = BUCKET_MINUTES * (BUCKET_COUNT as i64 - 1 - i as i64);
            let bucket_time = grid_end - chrono::Duration::minutes(offset_minutes);
            let key = bucket_time.format("%Y-%m-%d %H:%M:%S").to_string();
            let (total, blocked, forwarded) = bucket_map.get(&key).copied().unwrap_or((0, 0, 0));
            HistoryBucket {
                timestamp: bucket_time.timestamp(),
                total,
                blocked,
                cached: 0,
                forwarded,
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
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopDomainsResponse>, PiholeApiError> {
    Ok(Json(top_domains(&state, &params, true).await?))
}

async fn top_domains(
    state: &PiholeAppState,
    params: &DatabaseQueryParams,
    blocked: bool,
) -> Result<TopDomainsResponse, DomainError> {
    let period = params.period();
    let limit = params.limit();

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
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopClientsResponse>, PiholeApiError> {
    let period = params.period();
    let limit = params.limit();

    let (clients_raw, stats) = tokio::join!(
        async {
            if params.blocked.unwrap_or(false) {
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
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<TopDomainsResponse>, PiholeApiError> {
    let blocked = params.blocked.unwrap_or(false);
    Ok(Json(top_domains(&state, &params, blocked).await?))
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
    Query(params): Query<DatabaseQueryParams>,
) -> Result<Json<UpstreamsResponse>, PiholeApiError> {
    let stats = state.query.get_stats.execute(params.period()).await?;

    let mut per_server: HashMap<&str, u64> = HashMap::new();
    for (key, count) in &stats.source_stats {
        // Upstream keys are `{pool}:{server}`; the other keys have no colon.
        if let Some((_pool, server)) = key.split_once(':') {
            *per_server.entry(server).or_default() += count;
        }
    }
    let forwarded_queries: u64 = per_server.values().sum();

    let mut servers: Vec<(&str, u64)> = per_server.into_iter().collect();
    servers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

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

    Ok(Json(UpstreamsResponse {
        upstreams,
        forwarded_queries,
        total_queries: stats.queries_total,
    }))
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
    let port = match &protocol {
        DnsProtocol::Udp { addr }
        | DnsProtocol::Tcp { addr }
        | DnsProtocol::Tls { addr, .. }
        | DnsProtocol::Quic { addr, .. } => addr.port(),
        DnsProtocol::Https { port, .. } | DnsProtocol::H3 { port, .. } => *port,
    };
    UpstreamEntry {
        ip: protocol.socket_addr().map(|addr| addr.ip().to_string()),
        name: protocol.hostname().map(str::to_owned),
        port: i32::from(port),
        count,
        statistics: UpstreamStatistics::default(),
    }
}

/// Pi-hole v6 GET /api/stats/recent_blocked
///
/// Returns the most recently blocked domain.
#[utoipa::path(
    get,
    path = "/stats/recent_blocked",
    tag = "pihole:stats",
    responses(
        (status = 200, description = "Most recently blocked domain", body = RecentBlockedResponse)
    ),
    security(("session_id" = []))
)]
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
