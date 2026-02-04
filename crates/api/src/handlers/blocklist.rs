use crate::{dto::BlocklistResponse, state::AppState};
use axum::{extract::State, Json};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_blocklist")]
pub async fn get_blocklist(State(state): State<AppState>) -> Json<Vec<BlocklistResponse>> {
    debug!("Fetching blocklist");

    match state.get_blocklist.execute().await {
        Ok(domains) => {
            debug!(count = domains.len(), "Blocklist retrieved successfully");

            let response = domains
                .into_iter()
                .map(|d| BlocklistResponse {
                    domain: d.domain,
                    added_at: d.added_at.unwrap_or_default(),
                })
                .collect();

            Json(response)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve blocklist");
            Json(vec![])
        }
    }
}
