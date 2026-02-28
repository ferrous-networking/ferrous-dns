use crate::{
    dto::{BlocklistQuery, BlocklistResponse, PaginatedBlocklist},
    errors::ApiError,
    state::AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_blocklist")]
pub async fn get_blocklist(
    State(state): State<AppState>,
    Query(params): Query<BlocklistQuery>,
) -> Result<Json<PaginatedBlocklist>, ApiError> {
    debug!(
        limit = params.limit,
        offset = params.offset,
        "Fetching blocklist"
    );

    let (domains, total) = state
        .blocking
        .get_blocklist
        .execute_paged(params.limit, params.offset)
        .await?;

    debug!(
        count = domains.len(),
        total, "Blocklist retrieved successfully"
    );

    let data = domains
        .into_iter()
        .map(|d| BlocklistResponse {
            domain: d.domain,
            added_at: d.added_at.unwrap_or_default(),
        })
        .collect();

    Ok(Json(PaginatedBlocklist {
        data,
        total,
        limit: params.limit,
        offset: params.offset,
    }))
}
