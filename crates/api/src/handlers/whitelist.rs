use crate::{dto::WhitelistResponse, errors::ApiError, state::AppState};
use axum::{extract::State, Json};
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_whitelist")]
pub async fn get_whitelist(
    State(state): State<AppState>,
) -> Result<Json<Vec<WhitelistResponse>>, ApiError> {
    debug!("Fetching whitelist");

    let domains = state.blocking.get_whitelist.execute().await?;
    debug!(count = domains.len(), "Whitelist retrieved successfully");

    let response = domains
        .into_iter()
        .map(|d| WhitelistResponse {
            domain: d.domain,
            added_at: d.added_at.unwrap_or_default(),
        })
        .collect();

    Ok(Json(response))
}
