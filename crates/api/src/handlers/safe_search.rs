use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use ferrous_dns_domain::DomainError;

use crate::{
    dto::{SafeSearchConfigResponse, ToggleSafeSearchRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/safe-search/configs", get(get_all_configs))
        .route("/safe-search/configs/{group_id}", get(get_configs_by_group))
        .route("/safe-search/configs/{group_id}", post(toggle_config))
        .route(
            "/safe-search/configs/{group_id}",
            delete(delete_configs_by_group),
        )
}

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

async fn delete_configs_by_group(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.safe_search.delete_configs.execute(group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
