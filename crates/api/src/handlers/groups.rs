use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{ClientResponse, CreateGroupRequest, GroupResponse, UpdateGroupRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_groups, create_group))
        .routes(routes!(get_group_by_id, update_group, delete_group))
        .routes(routes!(get_group_clients))
}

#[utoipa::path(
    get,
    path = "/groups",
    tag = "groups",
    responses(
        (status = 200, description = "All groups", body = [GroupResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_groups(
    State(state): State<AppState>,
) -> Result<Json<Vec<GroupResponse>>, ApiError> {
    let groups_with_counts = state.groups.get_groups.get_all_with_client_counts().await?;
    let responses: Vec<GroupResponse> = groups_with_counts
        .into_iter()
        .map(|(group, count)| GroupResponse::from_group(group, Some(count)))
        .collect();
    debug!(count = responses.len(), "Groups retrieved successfully");
    Ok(Json(responses))
}

#[utoipa::path(
    get,
    path = "/groups/{id}",
    tag = "groups",
    params(("id" = i64, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group detail", body = GroupResponse),
        (status = 404, description = "Group not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_group_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<GroupResponse>, ApiError> {
    let group = state
        .groups
        .get_groups
        .get_by_id(id)
        .await?
        .ok_or_else(|| {
            ApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                "Group {} not found",
                id
            )))
        })?;
    let client_count = state
        .groups
        .get_groups
        .count_clients_in_group(id)
        .await
        .ok();
    Ok(Json(GroupResponse::from_group(group, client_count)))
}

#[utoipa::path(
    post,
    path = "/groups",
    tag = "groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "Group created", body = GroupResponse),
        (status = 409, description = "Conflict"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_group(
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupResponse>), ApiError> {
    let group = state
        .groups
        .create_group
        .execute(req.name, req.comment)
        .await?;
    let client_count = state
        .groups
        .get_groups
        .count_clients_in_group(group.id.unwrap_or(0))
        .await
        .ok();
    Ok((
        StatusCode::CREATED,
        Json(GroupResponse::from_group(group, client_count)),
    ))
}

#[utoipa::path(
    put,
    path = "/groups/{id}",
    tag = "groups",
    params(("id" = i64, Path, description = "Group ID")),
    request_body = UpdateGroupRequest,
    responses(
        (status = 200, description = "Group updated", body = GroupResponse),
        (status = 404, description = "Group not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>, ApiError> {
    let group = state
        .groups
        .update_group
        .execute(id, req.name, req.enabled, req.comment)
        .await?;
    let client_count = state
        .groups
        .get_groups
        .count_clients_in_group(id)
        .await
        .ok();
    Ok(Json(GroupResponse::from_group(group, client_count)))
}

#[utoipa::path(
    delete,
    path = "/groups/{id}",
    tag = "groups",
    params(("id" = i64, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 404, description = "Group not found"),
        (status = 409, description = "Group has assigned clients"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.groups.delete_group.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/groups/{id}/clients",
    tag = "groups",
    params(("id" = i64, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Clients in group", body = [ClientResponse]),
        (status = 404, description = "Group not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_group_clients(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<ClientResponse>>, ApiError> {
    let clients = state.groups.get_groups.get_clients_in_group(id).await?;
    let response: Vec<ClientResponse> = clients
        .into_iter()
        .map(|c| ClientResponse {
            id: c.id.unwrap_or(0),
            ip_address: c.ip_address.to_string(),
            mac_address: c.mac_address.map(|s| s.to_string()),
            hostname: c.hostname.map(|s| s.to_string()),
            first_seen: c.first_seen.unwrap_or_default(),
            last_seen: c.last_seen.unwrap_or_default(),
            query_count: c.query_count,
            group_id: c.group_id,
        })
        .collect();
    Ok(Json(response))
}
