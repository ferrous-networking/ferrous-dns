use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{CreateRegexFilterRequest, RegexFilterResponse, UpdateRegexFilterRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_regex_filters, create_regex_filter))
        .routes(routes!(
            get_regex_filter_by_id,
            update_regex_filter,
            delete_regex_filter
        ))
}

#[utoipa::path(
    get,
    path = "/regex-filters",
    tag = "blocking",
    responses(
        (status = 200, description = "All regex filters", body = [RegexFilterResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    get,
    path = "/regex-filters/{id}",
    tag = "blocking",
    params(("id" = i64, Path, description = "Regex filter ID")),
    responses(
        (status = 200, description = "Regex filter detail", body = RegexFilterResponse),
        (status = 404, description = "Regex filter not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/regex-filters",
    tag = "blocking",
    request_body = CreateRegexFilterRequest,
    responses(
        (status = 201, description = "Regex filter created", body = RegexFilterResponse),
        (status = 400, description = "Invalid input"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    put,
    path = "/regex-filters/{id}",
    tag = "blocking",
    params(("id" = i64, Path, description = "Regex filter ID")),
    request_body = UpdateRegexFilterRequest,
    responses(
        (status = 200, description = "Regex filter updated", body = RegexFilterResponse),
        (status = 404, description = "Regex filter not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    delete,
    path = "/regex-filters/{id}",
    tag = "blocking",
    params(("id" = i64, Path, description = "Regex filter ID")),
    responses(
        (status = 204, description = "Regex filter deleted"),
        (status = 404, description = "Regex filter not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_regex_filter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_regex_filter.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
