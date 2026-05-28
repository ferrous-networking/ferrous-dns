use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{SafeSearchConfigResponse, ToggleSafeSearchRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_configs))
        .routes(routes!(
            get_configs_by_group,
            toggle_config,
            delete_configs_by_group
        ))
}

#[utoipa::path(
    get,
    path = "/safe-search/configs",
    tag = "safe_search",
    responses(
        (status = 200, description = "All Safe Search configurations", body = [SafeSearchConfigResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_configs(
    State(state): State<AppState>,
) -> Result<Json<Vec<SafeSearchConfigResponse>>, ApiError> {
    let configs = state.safe_search.get_configs.get_all().await?;
    Ok(Json(
        configs
            .into_iter()
            .map(SafeSearchConfigResponse::from_entity)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/safe-search/configs/{group_id}",
    tag = "safe_search",
    params(("group_id" = i64, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group's Safe Search configurations", body = [SafeSearchConfigResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_configs_by_group(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<Json<Vec<SafeSearchConfigResponse>>, ApiError> {
    let configs = state.safe_search.get_configs.get_by_group(group_id).await?;
    Ok(Json(
        configs
            .into_iter()
            .map(SafeSearchConfigResponse::from_entity)
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/safe-search/configs/{group_id}",
    tag = "safe_search",
    params(("group_id" = i64, Path, description = "Group ID")),
    request_body = ToggleSafeSearchRequest,
    responses(
        (status = 200, description = "Safe Search configuration updated", body = SafeSearchConfigResponse),
        (status = 400, description = "Invalid engine"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn toggle_config(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(req): Json<ToggleSafeSearchRequest>,
) -> Result<Json<SafeSearchConfigResponse>, ApiError> {
    let engine = req.parse_engine().ok_or_else(|| {
        ApiError(DomainError::InvalidDomainName(format!(
            "Unknown Safe Search engine: '{}'",
            req.engine
        )))
    })?;
    let youtube_mode = req.parse_youtube_mode();

    let config = state
        .safe_search
        .toggle
        .execute(group_id, engine, req.enabled, youtube_mode)
        .await?;

    Ok(Json(SafeSearchConfigResponse::from_entity(config)))
}

#[utoipa::path(
    delete,
    path = "/safe-search/configs/{group_id}",
    tag = "safe_search",
    params(("group_id" = i64, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Safe Search configurations cleared for group"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_configs_by_group(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.safe_search.delete_configs.execute(group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
