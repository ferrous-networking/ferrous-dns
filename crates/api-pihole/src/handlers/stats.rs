use axum::{extract::State, Json};
use chrono::DateTime;
use ferrous_dns_application::ports::TimeGranularity;
use std::collections::HashMap;

use crate::{
    dto::stats::{
        ClientSummary, GravitySummary, HistoryBucket, HistoryResponse, QuerySummary,
        QueryTypesResponse, SummaryResponse, TopBlockedResponse, TopClientsResponse,
    },
    errors::PiholeApiError,
    state::PiholeAppState,
};

const STATS_PERIOD_HOURS: f32 = 24.0;
const TOP_ITEMS_LIMIT: u32 = 25;

/// Pi-hole v6 GET /api/stats/summary
///
/// Returns DNS query statistics in Pi-hole v6 schema so third-party dashboards
/// (e.g. Gravity Sync, Pihole-Exporter, HomeAssistant integration) work without
/// modification.
pub async fn get_summary(
    State(state): State<PiholeAppState>,
) -> Result<Json<SummaryResponse>, PiholeApiError> {
    let stats = state.get_stats.execute(STATS_PERIOD_HOURS).await?;

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
        .map(|(record_type, count)| (format!("{record_type:?}"), count))
        .collect();

    let response = SummaryResponse {
        queries: QuerySummary {
            total,
            blocked,
            percent_blocked,
            unique_domains: 0,
            forwarded,
            cached: cache_hits,
            frequency: 0.0,
            types: query_types,
        },
        clients: ClientSummary {
            active: stats.unique_clients,
            total: stats.unique_clients,
        },
        gravity: GravitySummary {
            domains_being_blocked: 0,
        },
        status: "enabled",
    };

    Ok(Json(response))
}

/// Pi-hole v6 GET /api/stats/history
///
/// Returns query history bucketed into 10-minute intervals for the last 24
/// hours, matching the Pi-hole v6 timeline format consumed by most dashboards.
pub async fn get_history(
    State(state): State<PiholeAppState>,
) -> Result<Json<HistoryResponse>, PiholeApiError> {
    let buckets = state
        .get_timeline
        .execute(24, TimeGranularity::QuarterHour)
        .await?;

    let history: Vec<HistoryBucket> = buckets
        .into_iter()
        .filter_map(|b| {
            let timestamp_str = if b.timestamp.ends_with('Z') {
                b.timestamp.clone()
            } else {
                format!("{}Z", b.timestamp.replace(' ', "T"))
            };
            let ts = DateTime::parse_from_rfc3339(&timestamp_str)
                .ok()?
                .timestamp();
            Some(HistoryBucket {
                timestamp: ts,
                total: b.total,
                blocked: b.blocked,
            })
        })
        .collect();

    Ok(Json(HistoryResponse { history }))
}

/// Pi-hole v6 GET /api/stats/top_blocked
///
/// Returns the top blocked domains in Pi-hole v6 format.
pub async fn get_top_blocked(
    State(state): State<PiholeAppState>,
) -> Result<Json<TopBlockedResponse>, PiholeApiError> {
    let domains = state
        .get_top_blocked_domains
        .execute(TOP_ITEMS_LIMIT, STATS_PERIOD_HOURS)
        .await?;

    let top_blocked: HashMap<String, u64> = domains.into_iter().collect();

    Ok(Json(TopBlockedResponse { top_blocked }))
}

/// Pi-hole v6 GET /api/stats/top_clients
///
/// Returns the top clients in Pi-hole v6 format.
/// Key format: `"<ip>|<hostname>"` (hostname is empty string when unknown).
pub async fn get_top_clients(
    State(state): State<PiholeAppState>,
) -> Result<Json<TopClientsResponse>, PiholeApiError> {
    let clients = state
        .get_top_clients
        .execute(TOP_ITEMS_LIMIT, STATS_PERIOD_HOURS)
        .await?;

    let top_sources: HashMap<String, u64> = clients
        .into_iter()
        .map(|(ip, hostname, count)| {
            let key = format!("{}|{}", ip, hostname.unwrap_or_default());
            (key, count)
        })
        .collect();

    Ok(Json(TopClientsResponse { top_sources }))
}

/// Pi-hole v6 GET /api/stats/query_types
///
/// Returns per-type query percentages in Pi-hole v6 format.
pub async fn get_query_types(
    State(state): State<PiholeAppState>,
) -> Result<Json<QueryTypesResponse>, PiholeApiError> {
    let stats = state.get_stats.execute(STATS_PERIOD_HOURS).await?;

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
            (format!("{record_type:?}"), pct)
        })
        .collect();

    Ok(Json(QueryTypesResponse { querytypes }))
}
