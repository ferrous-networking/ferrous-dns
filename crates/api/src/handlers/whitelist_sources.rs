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
    dto::{CreateWhitelistSourceRequest, UpdateWhitelistSourceRequest, WhitelistSourceResponse},
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
) -> Json<Vec<WhitelistSourceResponse>> {
    match state.get_whitelist_sources.get_all().await {
        Ok(sources) => {
            debug!(
                count = sources.len(),
                "Whitelist sources retrieved successfully"
            );
            Json(
                sources
                    .into_iter()
                    .map(WhitelistSourceResponse::from_source)
                    .collect(),
            )
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve whitelist sources");
            Json(vec![])
        }
    }
}

async fn get_whitelist_source_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<WhitelistSourceResponse>, (StatusCode, String)> {
    match state.get_whitelist_sources.get_by_id(id).await {
        Ok(Some(source)) => Ok(Json(WhitelistSourceResponse::from_source(source))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("Whitelist source {} not found", id),
        )),
        Err(e) => {
            error!(error = %e, "Failed to retrieve whitelist source");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn create_whitelist_source(
    State(state): State<AppState>,
    Json(req): Json<CreateWhitelistSourceRequest>,
) -> Result<(StatusCode, Json<WhitelistSourceResponse>), (StatusCode, String)> {
    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    match state
        .create_whitelist_source
        .execute(req.name, req.url, group_id, req.comment, enabled)
        .await
    {
        Ok(source) => Ok((
            StatusCode::CREATED,
            Json(WhitelistSourceResponse::from_source(source)),
        )),
        Err(DomainError::InvalidWhitelistSource(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to create whitelist source");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

async fn update_whitelist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateWhitelistSourceRequest>,
) -> Result<Json<WhitelistSourceResponse>, (StatusCode, String)> {
    match state
        .update_whitelist_source
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
        Ok(source) => Ok(Json(WhitelistSourceResponse::from_source(source))),
        Err(e @ DomainError::WhitelistSourceNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, e.to_string()))
        }
        Err(DomainError::InvalidWhitelistSource(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to update whitelist source");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_whitelist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_whitelist_source.execute(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e @ DomainError::WhitelistSourceNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, e.to_string()))
        }
        Err(e) => {
            error!(error = %e, "Failed to delete whitelist source");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
