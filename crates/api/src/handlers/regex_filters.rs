use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use tracing::{debug, error};

use crate::{
    dto::{CreateRegexFilterRequest, RegexFilterResponse, UpdateRegexFilterRequest},
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

async fn get_all_regex_filters(State(state): State<AppState>) -> Json<Vec<RegexFilterResponse>> {
    match state.get_regex_filters.get_all().await {
        Ok(filters) => {
            debug!(
                count = filters.len(),
                "Regex filters retrieved successfully"
            );
            Json(
                filters
                    .into_iter()
                    .map(RegexFilterResponse::from_domain)
                    .collect(),
            )
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve regex filters");
            Json(vec![])
        }
    }
}

async fn get_regex_filter_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<RegexFilterResponse>, (StatusCode, String)> {
    match state.get_regex_filters.get_by_id(id).await {
        Ok(Some(filter)) => Ok(Json(RegexFilterResponse::from_domain(filter))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("Regex filter {} not found", id),
        )),
        Err(e) => {
            error!(error = %e, "Failed to retrieve regex filter");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn create_regex_filter(
    State(state): State<AppState>,
    Json(req): Json<CreateRegexFilterRequest>,
) -> Result<(StatusCode, Json<RegexFilterResponse>), (StatusCode, String)> {
    let action = req.action.parse::<DomainAction>().ok().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid action '{}': must be 'allow' or 'deny'", req.action),
        )
    })?;

    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    match state
        .create_regex_filter
        .execute(
            req.name,
            req.pattern,
            action,
            group_id,
            req.comment,
            enabled,
        )
        .await
    {
        Ok(filter) => Ok((
            StatusCode::CREATED,
            Json(RegexFilterResponse::from_domain(filter)),
        )),
        Err(DomainError::InvalidRegexFilter(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(DomainError::GroupNotFound(msg)) => Err((StatusCode::BAD_REQUEST, msg)),
        Err(e) => {
            error!(error = %e, "Failed to create regex filter");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

async fn update_regex_filter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRegexFilterRequest>,
) -> Result<Json<RegexFilterResponse>, (StatusCode, String)> {
    let action = match req.action {
        Some(ref s) => Some(s.parse::<DomainAction>().ok().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid action '{}': must be 'allow' or 'deny'", s),
            )
        })?),
        None => None,
    };

    match state
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
        .await
    {
        Ok(filter) => Ok(Json(RegexFilterResponse::from_domain(filter))),
        Err(DomainError::RegexFilterNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(DomainError::InvalidRegexFilter(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(DomainError::GroupNotFound(msg)) => Err((StatusCode::BAD_REQUEST, msg)),
        Err(e) => {
            error!(error = %e, "Failed to update regex filter");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_regex_filter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_regex_filter.execute(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(DomainError::RegexFilterNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(e) => {
            error!(error = %e, "Failed to delete regex filter");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
