use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{CreateWhitelistSourceRequest, UpdateWhitelistSourceRequest, WhitelistSourceResponse},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_whitelist_sources, create_whitelist_source))
        .routes(routes!(
            get_whitelist_source_by_id,
            update_whitelist_source,
            delete_whitelist_source
        ))
}

#[utoipa::path(
    get,
    path = "/whitelist-sources",
    tag = "whitelist_sources",
    responses(
        (status = 200, description = "All whitelist sources", body = [WhitelistSourceResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    get,
    path = "/whitelist-sources/{id}",
    tag = "whitelist_sources",
    params(("id" = i64, Path, description = "Source ID")),
    responses(
        (status = 200, description = "Source detail", body = WhitelistSourceResponse),
        (status = 404, description = "Source not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/whitelist-sources",
    tag = "whitelist_sources",
    request_body = CreateWhitelistSourceRequest,
    responses(
        (status = 201, description = "Source created", body = WhitelistSourceResponse),
        (status = 409, description = "Conflict"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_whitelist_source(
    State(state): State<AppState>,
    Json(req): Json<CreateWhitelistSourceRequest>,
) -> Result<(StatusCode, Json<WhitelistSourceResponse>), ApiError> {
    let group_ids = req.resolved_group_ids(1);
    let enabled = req.enabled.unwrap_or(true);

    let source = state
        .blocking
        .create_whitelist_source
        .execute(req.name, req.url, group_ids, req.comment, enabled)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(WhitelistSourceResponse::from_source(source)),
    ))
}

#[utoipa::path(
    put,
    path = "/whitelist-sources/{id}",
    tag = "whitelist_sources",
    params(("id" = i64, Path, description = "Source ID")),
    request_body = UpdateWhitelistSourceRequest,
    responses(
        (status = 200, description = "Source updated", body = WhitelistSourceResponse),
        (status = 404, description = "Source not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_whitelist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateWhitelistSourceRequest>,
) -> Result<Json<WhitelistSourceResponse>, ApiError> {
    let group_ids = req.resolved_group_ids();
    let source = state
        .blocking
        .update_whitelist_source
        .execute(id, req.name, req.url, group_ids, req.comment, req.enabled)
        .await?;
    Ok(Json(WhitelistSourceResponse::from_source(source)))
}

#[utoipa::path(
    delete,
    path = "/whitelist-sources/{id}",
    tag = "whitelist_sources",
    params(("id" = i64, Path, description = "Source ID")),
    responses(
        (status = 204, description = "Source deleted"),
        (status = 404, description = "Source not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_whitelist_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_whitelist_source.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
