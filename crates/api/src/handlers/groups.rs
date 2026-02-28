use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use tracing::debug;

use crate::{
    dto::{ClientResponse, CreateGroupRequest, GroupResponse, UpdateGroupRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/groups", get(get_all_groups))
        .route("/groups", post(create_group))
        .route("/groups/{id}", get(get_group_by_id))
        .route("/groups/{id}", put(update_group))
        .route("/groups/{id}", delete(delete_group))
        .route("/groups/{id}/clients", get(get_group_clients))
}

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

async fn delete_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.groups.delete_group.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

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
