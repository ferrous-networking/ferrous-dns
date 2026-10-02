use crate::{
    dto::{DnssecStatsResponse, StatsQuery},
    errors::ApiError,
    state::AppState,
    utils::period_hours,
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::instrument;

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
    let stats = state
        .query
        .get_stats
        .execute_dnssec(period_hours(&params.period))
        .await?;
    let validator = state.dns.dnssec_stats.validator_stats();

    Ok(Json(DnssecStatsResponse {
        total: stats.total,
        validated: stats.validated,
        secure: stats.secure,
        insecure: stats.insecure,
        bogus: stats.bogus,
        indeterminate: stats.indeterminate,
        ds_denials_unproven: validator.ds_denials_unproven,
    }))
}
