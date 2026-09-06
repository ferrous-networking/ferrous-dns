use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{BlocklistSourceResponse, CreateBlocklistSourceRequest, UpdateBlocklistSourceRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_blocklist_sources, create_blocklist_source))
        .routes(routes!(sync_blocklist_sources))
        .routes(routes!(
            get_blocklist_source_by_id,
            update_blocklist_source,
            delete_blocklist_source
        ))
}

#[utoipa::path(
    get,
    path = "/blocklist-sources",
    tag = "blocklist_sources",
    responses(
        (status = 200, description = "All blocklist sources", body = [BlocklistSourceResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/blocklist-sources/sync",
    tag = "blocklist_sources",
    responses(
        (status = 202, description = "Sync started; sources download in the background"),
        (status = 409, description = "A sync is already running"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn sync_blocklist_sources(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    let started = state.blocking.sync_blocklist_sources.execute().await?;
    Ok(if started {
        StatusCode::ACCEPTED
    } else {
        StatusCode::CONFLICT
    })
}

#[utoipa::path(
    get,
    path = "/blocklist-sources/{id}",
    tag = "blocklist_sources",
    params(("id" = i64, Path, description = "Source ID")),
    responses(
        (status = 200, description = "Source detail", body = BlocklistSourceResponse),
        (status = 404, description = "Source not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/blocklist-sources",
    tag = "blocklist_sources",
    request_body = CreateBlocklistSourceRequest,
    responses(
        (status = 201, description = "Source created", body = BlocklistSourceResponse),
        (status = 409, description = "Conflict"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_blocklist_source(
    State(state): State<AppState>,
    Json(req): Json<CreateBlocklistSourceRequest>,
) -> Result<(StatusCode, Json<BlocklistSourceResponse>), ApiError> {
    let group_ids = req.resolved_group_ids(1);
    let enabled = req.enabled.unwrap_or(true);

    let source = state
        .blocking
        .create_blocklist_source
        .execute(req.name, req.url, group_ids, req.comment, enabled)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(BlocklistSourceResponse::from_source(source)),
    ))
}

#[utoipa::path(
    put,
    path = "/blocklist-sources/{id}",
    tag = "blocklist_sources",
    params(("id" = i64, Path, description = "Source ID")),
    request_body = UpdateBlocklistSourceRequest,
    responses(
        (status = 200, description = "Source updated", body = BlocklistSourceResponse),
        (status = 404, description = "Source not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_blocklist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateBlocklistSourceRequest>,
) -> Result<Json<BlocklistSourceResponse>, ApiError> {
    let group_ids = req.resolved_group_ids();
    let source = state
        .blocking
        .update_blocklist_source
        .execute(id, req.name, req.url, group_ids, req.comment, req.enabled)
        .await?;
    Ok(Json(BlocklistSourceResponse::from_source(source)))
}

#[utoipa::path(
    delete,
    path = "/blocklist-sources/{id}",
    tag = "blocklist_sources",
    params(("id" = i64, Path, description = "Source ID")),
    responses(
        (status = 204, description = "Source deleted"),
        (status = 404, description = "Source not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_blocklist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_blocklist_source.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
