use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use tracing::debug;

use crate::{
    dto::{CreateRegexFilterRequest, RegexFilterResponse, UpdateRegexFilterRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/regex-filters", get(get_all_regex_filters))
        .route("/regex-filters", post(create_regex_filter))
        .route("/regex-filters/{id}", get(get_regex_filter_by_id))
        .route("/regex-filters/{id}", put(update_regex_filter))
        .route("/regex-filters/{id}", delete(delete_regex_filter))
}

async fn get_all_regex_filters(
    State(state): State<AppState>,
) -> Result<Json<Vec<RegexFilterResponse>>, ApiError> {
    let filters = state.blocking.get_regex_filters.get_all().await?;
    debug!(
        count = filters.len(),
        "Regex filters retrieved successfully"
    );
    Ok(Json(
        filters
            .into_iter()
            .map(RegexFilterResponse::from_domain)
            .collect(),
    ))
}

async fn get_regex_filter_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<RegexFilterResponse>, ApiError> {
    let filter = state
        .blocking
        .get_regex_filters
        .get_by_id(id)
        .await?
        .ok_or_else(|| {
            ApiError(DomainError::NotFound(format!(
                "Regex filter {} not found",
                id
            )))
        })?;
    Ok(Json(RegexFilterResponse::from_domain(filter)))
}

async fn create_regex_filter(
    State(state): State<AppState>,
    Json(req): Json<CreateRegexFilterRequest>,
) -> Result<(StatusCode, Json<RegexFilterResponse>), ApiError> {
    let action = req.action.parse::<DomainAction>().ok().ok_or_else(|| {
        ApiError(DomainError::InvalidDomainName(format!(
            "Invalid action '{}': must be 'allow' or 'deny'",
            req.action
        )))
    })?;

    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    let filter = state
        .blocking
        .create_regex_filter
        .execute(
            req.name,
            req.pattern,
            action,
            group_id,
            req.comment,
            enabled,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegexFilterResponse::from_domain(filter)),
    ))
}

async fn update_regex_filter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRegexFilterRequest>,
) -> Result<Json<RegexFilterResponse>, ApiError> {
    let action = match req.action {
        Some(ref s) => Some(s.parse::<DomainAction>().ok().ok_or_else(|| {
            ApiError(DomainError::InvalidDomainName(format!(
                "Invalid action '{}': must be 'allow' or 'deny'",
                s
            )))
        })?),
        None => None,
    };

    let filter = state
        .blocking
        .update_regex_filter
        .execute(
            id,
            req.name,
            req.pattern,
            action,
            req.group_id,
            req.comment,
            req.enabled,
        )
        .await?;

    Ok(Json(RegexFilterResponse::from_domain(filter)))
}

async fn delete_regex_filter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_regex_filter.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
