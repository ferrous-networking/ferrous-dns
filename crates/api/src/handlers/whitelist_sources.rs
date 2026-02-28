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
    dto::{CreateWhitelistSourceRequest, UpdateWhitelistSourceRequest, WhitelistSourceResponse},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/whitelist-sources", get(get_all_whitelist_sources))
        .route("/whitelist-sources", post(create_whitelist_source))
        .route("/whitelist-sources/{id}", get(get_whitelist_source_by_id))
        .route("/whitelist-sources/{id}", put(update_whitelist_source))
        .route("/whitelist-sources/{id}", delete(delete_whitelist_source))
}

async fn get_all_whitelist_sources(
    State(state): State<AppState>,
) -> Result<Json<Vec<WhitelistSourceResponse>>, ApiError> {
    let sources = state.blocking.get_whitelist_sources.get_all().await?;
    debug!(
        count = sources.len(),
        "Whitelist sources retrieved successfully"
    );
    Ok(Json(
        sources
            .into_iter()
            .map(WhitelistSourceResponse::from_source)
            .collect(),
    ))
}

async fn get_whitelist_source_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<WhitelistSourceResponse>, ApiError> {
    let source = state
        .blocking
        .get_whitelist_sources
        .get_by_id(id)
        .await?
        .ok_or_else(|| {
            ApiError(DomainError::NotFound(format!(
                "Whitelist source {} not found",
                id
            )))
        })?;
    Ok(Json(WhitelistSourceResponse::from_source(source)))
}

async fn create_whitelist_source(
    State(state): State<AppState>,
    Json(req): Json<CreateWhitelistSourceRequest>,
) -> Result<(StatusCode, Json<WhitelistSourceResponse>), ApiError> {
    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    let source = state
        .blocking
        .create_whitelist_source
        .execute(req.name, req.url, group_id, req.comment, enabled)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(WhitelistSourceResponse::from_source(source)),
    ))
}

async fn update_whitelist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateWhitelistSourceRequest>,
) -> Result<Json<WhitelistSourceResponse>, ApiError> {
    let source = state
        .blocking
        .update_whitelist_source
        .execute(
            id,
            req.name,
            req.url,
            req.group_id,
            req.comment,
            req.enabled,
        )
        .await?;
    Ok(Json(WhitelistSourceResponse::from_source(source)))
}

async fn delete_whitelist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_whitelist_source.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
