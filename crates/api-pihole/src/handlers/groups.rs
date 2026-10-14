use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use ferrous_dns_domain::{DomainError, Group};

use crate::{
    dto::domains::BatchDeleteRequest,
    dto::groups::{CreateGroupRequest, GroupsResponse, PiholeGroupEntry, UpdateGroupRequest},
    errors::PiholeApiError,
    extract::PiholeJson,
    handlers::require_id,
    state::PiholeAppState,
};

fn group_to_entry(g: &Group) -> Result<PiholeGroupEntry, DomainError> {
    Ok(PiholeGroupEntry {
        id: require_id(g.id, "group")?,
        name: g.name.to_string(),
        enabled: g.enabled,
        comment: g.comment.as_ref().map(|c| c.to_string()),
        date_added: g.created_at.clone(),
        date_modified: g.updated_at.clone(),
    })
}

async fn find_group(state: &PiholeAppState, name: &str) -> Result<Group, DomainError> {
    state
        .groups
        .get_groups
        .get_all()
        .await?
        .into_iter()
        .find(|g| g.name.as_ref() == name)
        .ok_or_else(|| DomainError::NotFound(format!("Group {name} not found")))
}

/// Pi-hole v6 GET /api/groups — list all groups.
#[utoipa::path(
    get,
    path = "/groups",
    tag = "pihole:groups",
    responses(
        (status = 200, description = "All groups", body = GroupsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_all(
    State(state): State<PiholeAppState>,
) -> Result<Json<GroupsResponse>, PiholeApiError> {
    let groups = state.groups.get_groups.get_all().await?;
    let entries: Vec<PiholeGroupEntry> = groups
        .iter()
        .map(group_to_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(GroupsResponse { groups: entries }))
}

/// Pi-hole v6 POST /api/groups — create group.
#[utoipa::path(
    post,
    path = "/groups",
    tag = "pihole:groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "Group created", body = PiholeGroupEntry)
    ),
    security(("session_id" = []))
)]
pub async fn create_group(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<CreateGroupRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let result = state
        .groups
        .create_group
        .execute(body.name, body.comment, body.enabled.unwrap_or(true))
        .await?;
    Ok((StatusCode::CREATED, Json(group_to_entry(&result)?)))
}

/// Pi-hole v6 GET /api/groups/:name — get group by name.
#[utoipa::path(
    get,
    path = "/groups/{name}",
    tag = "pihole:groups",
    params(
        ("name" = String, Path, description = "Group name")
    ),
    responses(
        (status = 200, description = "Group entry", body = PiholeGroupEntry),
        (status = 404, description = "Group not found")
    ),
    security(("session_id" = []))
)]
pub async fn get_by_name(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
) -> Result<Json<PiholeGroupEntry>, PiholeApiError> {
    let group = find_group(&state, &name).await?;
    Ok(Json(group_to_entry(&group)?))
}

/// Pi-hole v6 PUT /api/groups/:name — update group.
#[utoipa::path(
    put,
    path = "/groups/{name}",
    tag = "pihole:groups",
    params(
        ("name" = String, Path, description = "Group name")
    ),
    request_body = UpdateGroupRequest,
    responses(
        (status = 200, description = "Group updated", body = PiholeGroupEntry),
        (status = 404, description = "Group not found")
    ),
    security(("session_id" = []))
)]
pub async fn update_group(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
    PiholeJson(body): PiholeJson<UpdateGroupRequest>,
) -> Result<Json<PiholeGroupEntry>, PiholeApiError> {
    let id = require_id(find_group(&state, &name).await?.id, "group")?;
    let result = state
        .groups
        .update_group
        .execute(id, body.name, body.enabled, body.comment)
        .await?;
    Ok(Json(group_to_entry(&result)?))
}

/// Pi-hole v6 DELETE /api/groups/:name — delete group.
#[utoipa::path(
    delete,
    path = "/groups/{name}",
    tag = "pihole:groups",
    params(
        ("name" = String, Path, description = "Group name")
    ),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 404, description = "Group not found")
    ),
    security(("session_id" = []))
)]
pub async fn delete_group(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, PiholeApiError> {
    let id = require_id(find_group(&state, &name).await?.id, "group")?;
    state.groups.delete_group.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Pi-hole v6 POST /api/groups:batchDelete — batch delete groups.
#[utoipa::path(
    post,
    path = "/groups:batchDelete",
    tag = "pihole:groups",
    request_body = BatchDeleteRequest,
    responses(
        (status = 204, description = "Batch delete completed")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<BatchDeleteRequest>,
) -> Result<StatusCode, PiholeApiError> {
    let groups = state.groups.get_groups.get_all().await?;
    for item in &body.items {
        if let Some(g) = groups.iter().find(|g| g.name.as_ref() == item.as_str()) {
            let id = require_id(g.id, "group")?;
            state.groups.delete_group.execute(id).await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
