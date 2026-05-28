use axum::{extract::State, Json};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{dto::block_filter::BlockFilterStatsResponse, state::AppState};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_block_filter_stats))
}

#[utoipa::path(
    get,
    path = "/block-filter/stats",
    tag = "block_filter",
    responses(
        (status = 200, description = "Block filter engine stats", body = BlockFilterStatsResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn get_block_filter_stats(
    State(state): State<AppState>,
) -> Json<BlockFilterStatsResponse> {
    let total = state.blocking.get_block_filter_stats.execute();
    Json(BlockFilterStatsResponse {
        total_blocked_domains: total,
    })
}
