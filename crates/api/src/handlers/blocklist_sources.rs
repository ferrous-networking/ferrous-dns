use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::DomainError;
use tracing::{debug, error};

use crate::{
    dto::{BlocklistSourceResponse, CreateBlocklistSourceRequest, UpdateBlocklistSourceRequest},
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
) -> Json<Vec<BlocklistSourceResponse>> {
    match state.get_blocklist_sources.get_all().await {
        Ok(sources) => {
            debug!(
                count = sources.len(),
                "Blocklist sources retrieved successfully"
            );
            Json(
                sources
                    .into_iter()
                    .map(BlocklistSourceResponse::from_source)
                    .collect(),
            )
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve blocklist sources");
            Json(vec![])
        }
    }
}

async fn get_blocklist_source_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<BlocklistSourceResponse>, (StatusCode, String)> {
    match state.get_blocklist_sources.get_by_id(id).await {
        Ok(Some(source)) => Ok(Json(BlocklistSourceResponse::from_source(source))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("Blocklist source {} not found", id),
        )),
        Err(e) => {
            error!(error = %e, "Failed to retrieve blocklist source");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn create_blocklist_source(
    State(state): State<AppState>,
    Json(req): Json<CreateBlocklistSourceRequest>,
) -> Result<(StatusCode, Json<BlocklistSourceResponse>), (StatusCode, String)> {
    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    match state
        .create_blocklist_source
        .execute(req.name, req.url, group_id, req.comment, enabled)
        .await
    {
        Ok(source) => Ok((
            StatusCode::CREATED,
            Json(BlocklistSourceResponse::from_source(source)),
        )),
        Err(DomainError::InvalidBlocklistSource(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to create blocklist source");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

async fn update_blocklist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateBlocklistSourceRequest>,
) -> Result<Json<BlocklistSourceResponse>, (StatusCode, String)> {
    match state
        .update_blocklist_source
        .execute(
            id,
            req.name,
            req.url,
            req.group_id,
            req.comment,
            req.enabled,
        )
        .await
    {
        Ok(source) => Ok(Json(BlocklistSourceResponse::from_source(source))),
        Err(e @ DomainError::BlocklistSourceNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, e.to_string()))
        }
        Err(DomainError::InvalidBlocklistSource(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to update blocklist source");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_blocklist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_blocklist_source.execute(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e @ DomainError::BlocklistSourceNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, e.to_string()))
        }
        Err(e) => {
            error!(error = %e, "Failed to delete blocklist source");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
