use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{CreateDohIdRequest, DohIdResponse, UpdateDohIdRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_doh_ids, create_doh_id))
        .routes(routes!(get_doh_id_by_id, update_doh_id, delete_doh_id))
}

async fn lookup_group_name(state: &AppState, group_id: i64) -> Option<String> {
    state
        .groups
        .get_groups
        .get_by_id(group_id)
        .await
        .ok()
        .flatten()
        .map(|g| g.name.to_string())
}

#[utoipa::path(
    get,
    path = "/doh-ids",
    tag = "doh_ids",
    responses(
        (status = 200, description = "All registered DoH IDs", body = [DohIdResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_doh_ids(
    State(state): State<AppState>,
) -> Result<Json<Vec<DohIdResponse>>, ApiError> {
    let entries = state.doh_ids.get_doh_ids.get_all().await?;
    let group_names: HashMap<i64, Arc<str>> = state
        .groups
        .get_groups
        .get_all()
        .await?
        .into_iter()
        .filter_map(|g| Some((g.id?, g.name)))
        .collect();

    let responses: Vec<DohIdResponse> = entries
        .into_iter()
        .map(|entry| {
            let group_name = group_names.get(&entry.group_id).map(|n| n.to_string());
            DohIdResponse::from_doh_id(entry, group_name)
        })
        .collect();

    debug!(count = responses.len(), "DoH IDs retrieved successfully");
    Ok(Json(responses))
}

#[utoipa::path(
    get,
    path = "/doh-ids/{id}",
    tag = "doh_ids",
    params(("id" = i64, Path, description = "DoH ID record ID")),
    responses(
        (status = 200, description = "DoH ID entry", body = DohIdResponse),
        (status = 404, description = "DoH ID not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_doh_id_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<DohIdResponse>, ApiError> {
    let entry = state
        .doh_ids
        .get_doh_ids
        .get_by_id(id)
        .await?
        .ok_or(DomainError::DohIdNotFound(id))?;
    let group_name = lookup_group_name(&state, entry.group_id).await;

    Ok(Json(DohIdResponse::from_doh_id(entry, group_name)))
}

#[utoipa::path(
    post,
    path = "/doh-ids",
    tag = "doh_ids",
    request_body = CreateDohIdRequest,
    responses(
        (status = 201, description = "DoH ID created", body = DohIdResponse),
        (status = 400, description = "Invalid DoH ID input"),
        (status = 404, description = "Group not found"),
        (status = 409, description = "Duplicate name or client_id"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_doh_id(
    State(state): State<AppState>,
    Json(req): Json<CreateDohIdRequest>,
) -> Result<(StatusCode, Json<DohIdResponse>), ApiError> {
    let created = state
        .doh_ids
        .create_doh_id
        .execute(req.name, req.client_id, req.group_id, req.comment)
        .await?;
    let group_name = lookup_group_name(&state, created.group_id).await;

    Ok((
        StatusCode::CREATED,
        Json(DohIdResponse::from_doh_id(created, group_name)),
    ))
}

#[utoipa::path(
    put,
    path = "/doh-ids/{id}",
    tag = "doh_ids",
    params(("id" = i64, Path, description = "DoH ID record ID")),
    request_body = UpdateDohIdRequest,
    responses(
        (status = 200, description = "DoH ID updated", body = DohIdResponse),
        (status = 400, description = "Invalid DoH ID input"),
        (status = 404, description = "DoH ID or group not found"),
        (status = 409, description = "Duplicate name or client_id"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_doh_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDohIdRequest>,
) -> Result<Json<DohIdResponse>, ApiError> {
    let updated = state
        .doh_ids
        .update_doh_id
        .execute(id, req.name, req.client_id, req.group_id, req.comment)
        .await?;
    let group_name = lookup_group_name(&state, updated.group_id).await;

    Ok(Json(DohIdResponse::from_doh_id(updated, group_name)))
}

#[utoipa::path(
    delete,
    path = "/doh-ids/{id}",
    tag = "doh_ids",
    params(("id" = i64, Path, description = "DoH ID record ID")),
    responses(
        (status = 204, description = "DoH ID deleted"),
        (status = 404, description = "DoH ID not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_doh_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.doh_ids.delete_doh_id.execute(id).await?;

    Ok(StatusCode::NO_CONTENT)
}
