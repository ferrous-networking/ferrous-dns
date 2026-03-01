use crate::{
    dto::{
        CacheStatsResponse, DashboardQuery, DashboardResponse, QueryRateResponse, StatsResponse,
        TimelineBucket, TimelineResponse, TopBlockedDomain, TopClient, TopType, TypeDistribution,
    },
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::{ports::TimeGranularity, use_cases::RateUnit};
use tracing::{error, instrument};

const DEFAULT_PERIOD_HOURS: f32 = 24.0;
const TOP_TYPES_LIMIT: usize = 10;

#[instrument(skip(state), name = "api_get_dashboard")]
pub async fn get_dashboard(
    State(state): State<AppState>,
    Query(params): Query<DashboardQuery>,
) -> Json<DashboardResponse> {
    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(DEFAULT_PERIOD_HOURS);

    let stats_state = state.clone();
    let rate_state = state.clone();
    let cache_state = state.clone();
    let top_blocked_state = state.clone();
    let top_clients_state = state.clone();

    let stats_fut = async move { stats_state.query.get_stats.execute(period_hours).await };
    let rate_fut = async move {
        rate_state
            .query
            .get_query_rate
            .execute(RateUnit::Second)
            .await
    };
    let cache_fut = async move {
        cache_state
            .query
            .get_cache_stats
            .execute(period_hours)
            .await
    };
    let top_blocked_fut = async move {
        top_blocked_state
            .query
            .get_top_blocked_domains
            .execute(15, period_hours)
            .await
    };
    let top_clients_fut = async move {
        top_clients_state
            .query
            .get_top_clients
            .execute(15, period_hours)
            .await
    };

    let (stats_result, rate_result, cache_result, top_blocked_result, top_clients_result, timeline) =
        if params.include_timeline {
            let timeline_state = state.clone();
            let period_u32 = period_hours as u32;
            let timeline_fut = async move {
                timeline_state
                    .query
                    .get_timeline
                    .execute(period_u32, TimeGranularity::QuarterHour)
                    .await
            };

            let (s, r, c, tb, tc, t) = tokio::join!(
                stats_fut,
                rate_fut,
                cache_fut,
                top_blocked_fut,
                top_clients_fut,
                timeline_fut
            );
            let timeline_resp = match t {
                Ok(buckets) => {
                    let buckets_dto: Vec<TimelineBucket> = buckets
                        .into_iter()
                        .map(|b| TimelineBucket {
                            timestamp: b.timestamp,
                            total: b.total,
                            blocked: b.blocked,
                            unblocked: b.unblocked,
                        })
                        .collect();
                    Some(TimelineResponse {
                        total_buckets: buckets_dto.len(),
                        period: params.period.clone(),
                        granularity: "15min".to_string(),
                        buckets: buckets_dto,
                    })
                }
                Err(e) => {
                    error!(error = %e, "Failed to retrieve timeline");
                    None
                }
            };
            (s, r, c, tb, tc, timeline_resp)
        } else {
            let (s, r, c, tb, tc) = tokio::join!(
                stats_fut,
                rate_fut,
                cache_fut,
                top_blocked_fut,
                top_clients_fut
            );
            (s, r, c, tb, tc, None)
        };

    let stats_resp = match stats_result {
        Ok(stats) => {
            let queries_by_type = stats
                .queries_by_type
                .iter()
                .map(|(rt, count)| (rt.as_str().to_string(), *count))
                .collect();

            let most_queried_type = stats.most_queried_type.map(|rt| rt.as_str().to_string());

            let record_type_distribution = stats
                .record_type_distribution
                .iter()
                .map(|(rt, pct)| TypeDistribution {
                    record_type: rt.as_str().to_string(),
                    percentage: *pct,
                })
                .collect();

            let top_10_types = stats
                .top_types(TOP_TYPES_LIMIT)
                .into_iter()
                .map(|(rt, count)| TopType {
                    record_type: rt.as_str().to_string(),
                    count,
                })
                .collect();

            StatsResponse {
                queries_total: stats.queries_total,
                queries_blocked: stats.queries_blocked,
                clients: stats.unique_clients,
                uptime: stats.uptime_seconds,
                cache_hit_rate: stats.cache_hit_rate,
                avg_query_time_ms: stats.avg_query_time_ms,
                avg_cache_time_ms: stats.avg_cache_time_ms,
                avg_upstream_time_ms: stats.avg_upstream_time_ms,
                queries_by_type,
                most_queried_type,
                record_type_distribution,
                top_10_types,
                source_stats: stats.source_stats,
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve statistics");
            StatsResponse::default()
        }
    };

    let rate_resp = match rate_result {
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

    let cache_resp = match cache_result {
        Ok(stats) => {
            let total_entries = state.dns.cache.cache_size();
            CacheStatsResponse {
                total_entries,
                total_hits: stats.total_hits,
                total_misses: stats.total_misses,
                total_refreshes: stats.total_refreshes,
                hit_rate: stats.hit_rate,
                refresh_rate: stats.refresh_rate,
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve cache stats");
            CacheStatsResponse {
                total_entries: 0,
                total_hits: 0,
                total_misses: 0,
                total_refreshes: 0,
                hit_rate: 0.0,
                refresh_rate: 0.0,
            }
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
        stats: stats_resp,
        rate: rate_resp,
        cache_stats: cache_resp,
        timeline,
        top_blocked_domains,
        top_clients,
    })
}
