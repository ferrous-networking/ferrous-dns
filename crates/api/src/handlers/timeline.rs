use crate::{
    dto::{TimelineBucket, TimelineQuery, TimelineResponse},
    errors::ApiError,
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::ports::TimeGranularity;
use tracing::{debug, instrument};

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
) -> Result<Json<TimelineResponse>, ApiError> {
    debug!(
        period = %params.period,
        granularity = %params.granularity,
        "Fetching query timeline"
    );

    let period_hours = parse_period(&params.period)
        .map(|h| validate_period(h) as u32)
        .unwrap_or(24);

    let granularity = parse_granularity(&params.granularity);

    let buckets = state
        .query
        .get_timeline
        .execute(period_hours, granularity)
        .await?;
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

    Ok(Json(TimelineResponse {
        total_buckets: buckets_dto.len(),
        period: params.period,
        granularity: params.granularity,
        buckets: buckets_dto,
    }))
}
