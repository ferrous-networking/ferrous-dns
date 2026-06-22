use crate::{
    dto::{DnssecStatsResponse, StatsQuery},
    errors::ApiError,
    state::AppState,
    utils::{parse_period, validate_period},
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::instrument;

const DEFAULT_PERIOD_HOURS: f32 = 24.0;

#[utoipa::path(
    get,
    path = "/dnssec/stats",
    tag = "dnssec",
    params(StatsQuery),
    responses(
        (status = 200, description = "Aggregated DNSSEC validation statistics", body = DnssecStatsResponse),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_dnssec_stats")]
pub async fn get_dnssec_stats(
    State(state): State<AppState>,
    Query(params): Query<StatsQuery>,
) -> Result<Json<DnssecStatsResponse>, ApiError> {
    let period_hours = parse_period(&params.period)
        .map(validate_period)
        .unwrap_or(DEFAULT_PERIOD_HOURS);

    let stats = state.query.get_stats.execute_dnssec(period_hours).await?;

    Ok(Json(DnssecStatsResponse {
        total: stats.total,
        validated: stats.validated,
        secure: stats.secure,
        insecure: stats.insecure,
        bogus: stats.bogus,
        indeterminate: stats.indeterminate,
    }))
}
