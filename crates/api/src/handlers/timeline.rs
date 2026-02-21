use crate::{
    dto::{TimelineBucket, TimelineQuery, TimelineResponse},
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::ports::TimeGranularity;
use tracing::{debug, error, instrument};

fn parse_granularity(s: &str) -> TimeGranularity {
    match s {
        "minute" => TimeGranularity::Minute,
        "15min" | "quarter_hour" => TimeGranularity::QuarterHour,
        "day" => TimeGranularity::Day,
        _ => TimeGranularity::Hour,
    }
}

#[instrument(skip(state), name = "api_get_timeline")]
pub async fn get_timeline(
    State(state): State<AppState>,
    Query(params): Query<TimelineQuery>,
) -> Json<TimelineResponse> {
    debug!(
        period = %params.period,
        granularity = %params.granularity,
        "Fetching query timeline"
    );

    let period_hours = parse_period(&params.period)
        .map(|h| validate_period(h) as u32)
        .unwrap_or(24);

    let granularity = parse_granularity(&params.granularity);

    match state.get_timeline.execute(period_hours, granularity).await {
        Ok(buckets) => {
            debug!(buckets = buckets.len(), "Timeline retrieved successfully");

            let buckets_dto: Vec<TimelineBucket> = buckets
                .into_iter()
                .map(|b| TimelineBucket {
                    timestamp: b.timestamp,
                    total: b.total,
                    blocked: b.blocked,
                    unblocked: b.unblocked,
                })
                .collect();

            Json(TimelineResponse {
                total_buckets: buckets_dto.len(),
                period: params.period,
                granularity: params.granularity,
                buckets: buckets_dto,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve timeline");
            Json(TimelineResponse {
                buckets: vec![],
                period: params.period,
                granularity: params.granularity,
                total_buckets: 0,
            })
        }
    }
}
