use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::DomainError;
use tracing::{debug, error};

use crate::{
    dto::{ClientResponse, CreateGroupRequest, GroupResponse, UpdateGroupRequest},
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

async fn get_all_groups(State(state): State<AppState>) -> Json<Vec<GroupResponse>> {
    match state.get_groups.get_all().await {
        Ok(groups) => {
            let mut responses = Vec::new();
            for group in groups {
                let client_count = state
                    .get_groups
                    .count_clients_in_group(group.id.unwrap_or(0))
                    .await
                    .ok();
                responses.push(GroupResponse::from_group(group, client_count));
            }
            debug!(count = responses.len(), "Groups retrieved successfully");
            Json(responses)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve groups");
            Json(vec![])
        }
    }
}

async fn get_group_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<GroupResponse>, (StatusCode, String)> {
    match state.get_groups.get_by_id(id).await {
        Ok(Some(group)) => {
            let client_count = state.get_groups.count_clients_in_group(id).await.ok();
            Ok(Json(GroupResponse::from_group(group, client_count)))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("Group {} not found", id))),
        Err(e) => {
            error!(error = %e, "Failed to retrieve group");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn create_group(
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupResponse>), (StatusCode, String)> {
    match state.create_group.execute(req.name, req.comment).await {
        Ok(group) => {
            let client_count = state
                .get_groups
                .count_clients_in_group(group.id.unwrap_or(0))
                .await
                .ok();
            Ok((
                StatusCode::CREATED,
                Json(GroupResponse::from_group(group, client_count)),
            ))
        }
        Err(DomainError::InvalidGroupName(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e) => {
            error!(error = %e, "Failed to create group");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

async fn update_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>, (StatusCode, String)> {
    match state
        .update_group
        .execute(id, req.name, req.enabled, req.comment)
        .await
    {
        Ok(group) => {
            let client_count = state.get_groups.count_clients_in_group(id).await.ok();
            Ok(Json(GroupResponse::from_group(group, client_count)))
        }
        Err(DomainError::GroupNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(DomainError::ProtectedGroupCannotBeDisabled) => Err((
            StatusCode::BAD_REQUEST,
            "Cannot disable the default Protected group".to_string(),
        )),
        Err(DomainError::InvalidGroupName(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e) => {
            error!(error = %e, "Failed to update group");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_group.execute(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(DomainError::GroupNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(DomainError::ProtectedGroupCannotBeDeleted) => Err((
            StatusCode::FORBIDDEN,
            "Cannot delete the default Protected group".to_string(),
        )),
        Err(DomainError::GroupHasAssignedClients(count)) => Err((
            StatusCode::CONFLICT,
            format!("Cannot delete group with {} assigned clients", count),
        )),
        Err(e) => {
            error!(error = %e, "Failed to delete group");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn get_group_clients(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<ClientResponse>>, (StatusCode, String)> {
    match state.get_groups.get_clients_in_group(id).await {
        Ok(clients) => {
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
        Err(e) => {
            error!(error = %e, "Failed to retrieve clients in group");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
