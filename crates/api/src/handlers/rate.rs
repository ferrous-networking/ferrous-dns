use crate::{
    dto::{QueryRateResponse, RateQuery},
    errors::ApiError,
    state::AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::use_cases::RateUnit;
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_query_rate")]
pub async fn get_query_rate(
    State(state): State<AppState>,
    Query(params): Query<RateQuery>,
) -> Result<Json<QueryRateResponse>, ApiError> {
    debug!(unit = %params.unit, "Fetching query rate");

    let rate_unit = match params.unit.as_str() {
        "second" => RateUnit::Second,
        "minute" => RateUnit::Minute,
        "hour" => RateUnit::Hour,
        _ => {
            debug!(unit = %params.unit, "Invalid unit, defaulting to second");
            RateUnit::Second
        }
    };

    let rate = state.query.get_query_rate.execute(rate_unit).await?;

    debug!(
        queries = rate.queries,
        rate = %rate.rate,
        "Query rate retrieved successfully"
    );

    Ok(Json(QueryRateResponse {
        queries: rate.queries,
        rate: rate.rate,
    }))
}
