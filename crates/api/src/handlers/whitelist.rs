use crate::{dto::WhitelistResponse, state::AppState};
use axum::{extract::State, Json};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_whitelist")]
pub async fn get_whitelist(State(state): State<AppState>) -> Json<Vec<WhitelistResponse>> {
    debug!("Fetching whitelist");

    match state.get_whitelist.execute().await {
        Ok(domains) => {
            debug!(count = domains.len(), "Whitelist retrieved successfully");

            let response = domains
                .into_iter()
                .map(|d| WhitelistResponse {
                    domain: d.domain,
                    added_at: d.added_at.unwrap_or_default(),
                })
                .collect();

            Json(response)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve whitelist");
            Json(vec![])
        }
    }
}
