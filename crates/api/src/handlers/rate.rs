use crate::{
    dto::{QueryRateResponse, RateQuery},
    state::AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use ferrous_dns_application::use_cases::RateUnit;
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_query_rate")]
pub async fn get_query_rate(
    State(state): State<AppState>,
    Query(params): Query<RateQuery>,
) -> Json<QueryRateResponse> {
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

    match state.get_query_rate.execute(rate_unit).await {
        Ok(rate) => {
            debug!(
                queries = rate.queries,
                rate = %rate.rate,
                "Query rate retrieved successfully"
            );

            Json(QueryRateResponse {
                queries: rate.queries,
                rate: rate.rate,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve query rate");
            Json(QueryRateResponse {
                queries: 0,
                rate: "0 q/s".to_string(),
            })
        }
    }
}
