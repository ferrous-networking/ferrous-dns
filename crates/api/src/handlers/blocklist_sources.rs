use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::DomainError;
use tracing::debug;

use crate::{
    dto::{BlocklistSourceResponse, CreateBlocklistSourceRequest, UpdateBlocklistSourceRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/blocklist-sources", get(get_all_blocklist_sources))
        .route("/blocklist-sources", post(create_blocklist_source))
        .route("/blocklist-sources/{id}", get(get_blocklist_source_by_id))
        .route("/blocklist-sources/{id}", put(update_blocklist_source))
        .route("/blocklist-sources/{id}", delete(delete_blocklist_source))
}

async fn get_all_blocklist_sources(
    State(state): State<AppState>,
) -> Result<Json<Vec<BlocklistSourceResponse>>, ApiError> {
    let sources = state.blocking.get_blocklist_sources.get_all().await?;
    debug!(
        count = sources.len(),
        "Blocklist sources retrieved successfully"
    );
    Ok(Json(
        sources
            .into_iter()
            .map(BlocklistSourceResponse::from_source)
            .collect(),
    ))
}

async fn get_blocklist_source_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<BlocklistSourceResponse>, ApiError> {
    let source = state
        .blocking
        .get_blocklist_sources
        .get_by_id(id)
        .await?
        .ok_or_else(|| {
            ApiError(DomainError::NotFound(format!(
                "Blocklist source {} not found",
                id
            )))
        })?;
    Ok(Json(BlocklistSourceResponse::from_source(source)))
}

async fn create_blocklist_source(
    State(state): State<AppState>,
    Json(req): Json<CreateBlocklistSourceRequest>,
) -> Result<(StatusCode, Json<BlocklistSourceResponse>), ApiError> {
    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    let source = state
        .blocking
        .create_blocklist_source
        .execute(req.name, req.url, group_id, req.comment, enabled)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(BlocklistSourceResponse::from_source(source)),
    ))
}

async fn update_blocklist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateBlocklistSourceRequest>,
) -> Result<Json<BlocklistSourceResponse>, ApiError> {
    let source = state
        .blocking
        .update_blocklist_source
        .execute(
            id,
            req.name,
            req.url,
            req.group_id,
            req.comment,
            req.enabled,
        )
        .await?;
    Ok(Json(BlocklistSourceResponse::from_source(source)))
}

async fn delete_blocklist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_blocklist_source.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
