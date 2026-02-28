use axum::{extract::State, routing::get, Json, Router};

use crate::{dto::block_filter::BlockFilterStatsResponse, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new().route("/block-filter/stats", get(get_block_filter_stats))
}

pub async fn get_block_filter_stats(
    State(state): State<AppState>,
) -> Json<BlockFilterStatsResponse> {
    let total = state.blocking.get_block_filter_stats.execute();
    Json(BlockFilterStatsResponse {
        total_blocked_domains: total,
    })
}
