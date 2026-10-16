use crate::{
    dto::{
        CacheStatsResponse, DashboardQuery, DashboardResponse, QueryRateResponse, StatsResponse,
        TimelineBucket, TimelineResponse, TopBlockedDomain, TopClient,
    },
    state::AppState,
    utils::period_hours,
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::{ports::TimeGranularity, use_cases::RateUnit};
use tracing::{error, instrument};

const TOP_LIMIT: u32 = 15;

#[utoipa::path(
    get,
    path = "/dashboard",
    tag = "dashboard",
    params(DashboardQuery),
    responses(
        (status = 200, description = "Aggregated dashboard payload", body = DashboardResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_dashboard")]
pub async fn get_dashboard(
    State(state): State<AppState>,
    Query(params): Query<DashboardQuery>,
) -> Json<DashboardResponse> {
    let period_hours = period_hours(&params.period);
    let q = &state.query;

    let timeline_fut = async {
        if params.include_timeline {
            Some(
                q.get_timeline
                    .execute(period_hours, TimeGranularity::QuarterHour)
                    .await,
            )
        } else {
            None
        }
    };

    let (stats_result, rate_result, cache_result, top_blocked_result, top_clients_result, timeline) = tokio::join!(
        q.get_stats.execute(period_hours),
        q.get_query_rate.execute(RateUnit::Second),
        q.get_cache_stats.execute(period_hours),
        q.get_top_blocked_domains.execute(TOP_LIMIT, period_hours),
        q.get_top_clients.execute(TOP_LIMIT, period_hours),
        timeline_fut,
    );

    let timeline = match timeline {
        Some(Ok(buckets)) => {
            let buckets: Vec<TimelineBucket> =
                buckets.into_iter().map(TimelineBucket::from).collect();
            Some(TimelineResponse {
                total_buckets: buckets.len(),
                period: params.period,
                granularity: TimeGranularity::QuarterHour.as_str().to_string(),
                buckets,
            })
        }
        Some(Err(e)) => {
            error!(error = %e, "Failed to retrieve timeline");
            None
        }
        None => None,
    };

    let stats = stats_result.map(StatsResponse::from).unwrap_or_else(|e| {
        error!(error = %e, "Failed to retrieve statistics");
        StatsResponse::default()
    });

    let rate = match rate_result {
        Ok(rate) => QueryRateResponse {
            queries: rate.queries,
            rate: rate.rate,
        },
        Err(e) => {
            error!(error = %e, "Failed to retrieve query rate");
            QueryRateResponse {
                queries: 0,
                rate: "0 q/s".to_string(),
            }
        }
    };

    let cache_stats = match cache_result {
        Ok(stats) => CacheStatsResponse::new(state.dns.cache.cache_size(), &stats),
        Err(e) => {
            error!(error = %e, "Failed to retrieve cache stats");
            CacheStatsResponse::default()
        }
    };

    let top_blocked_domains = match top_blocked_result {
        Ok(domains) => domains
            .into_iter()
            .map(|(domain, count)| TopBlockedDomain { domain, count })
            .collect(),
        Err(e) => {
            error!(error = %e, "Failed to retrieve top blocked domains");
            vec![]
        }
    };

    let top_clients = match top_clients_result {
        Ok(clients) => clients
            .into_iter()
            .map(|(ip, hostname, count)| TopClient {
                ip,
                hostname,
                count,
            })
            .collect(),
        Err(e) => {
            error!(error = %e, "Failed to retrieve top clients");
            vec![]
        }
    };

    Json(DashboardResponse {
        stats,
        rate,
        cache_stats,
        timeline,
        top_blocked_domains,
        top_clients,
        malware_detection_enabled: state.malware_detection_enabled,
    })
}
