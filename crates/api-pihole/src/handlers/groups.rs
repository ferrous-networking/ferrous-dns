use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::{
    dto::domains::BatchDeleteRequest,
    dto::groups::{CreateGroupRequest, GroupsResponse, PiholeGroupEntry, UpdateGroupRequest},
    errors::PiholeApiError,
    state::PiholeAppState,
};

fn group_to_entry(g: &ferrous_dns_domain::Group) -> Result<PiholeGroupEntry, PiholeApiError> {
    Ok(PiholeGroupEntry {
        id: g.id.ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                "group missing id".into(),
            ))
        })?,
        name: g.name.to_string(),
        enabled: g.enabled,
        comment: g.comment.as_ref().map(|c| c.to_string()),
        date_added: g.created_at.clone(),
        date_modified: g.updated_at.clone(),
    })
}

/// Pi-hole v6 GET /api/groups — list all groups.
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
pub async fn create_group(
    State(state): State<PiholeAppState>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let result = state
        .groups
        .create_group
        .execute(body.name, body.comment)
        .await?;
    Ok((StatusCode::CREATED, Json(group_to_entry(&result)?)))
}

/// Pi-hole v6 GET /api/groups/:name — get group by name.
pub async fn get_by_name(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
) -> Result<Json<PiholeGroupEntry>, PiholeApiError> {
    let groups = state.groups.get_groups.get_all().await?;
    let group = groups
        .iter()
        .find(|g| g.name.as_ref() == name)
        .ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                "Group {name} not found"
            )))
        })?;
    Ok(Json(group_to_entry(group)?))
}

/// Pi-hole v6 PUT /api/groups/:name — update group.
pub async fn update_group(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateGroupRequest>,
) -> Result<Json<PiholeGroupEntry>, PiholeApiError> {
    let groups = state.groups.get_groups.get_all().await?;
    let group = groups
        .iter()
        .find(|g| g.name.as_ref() == name)
        .ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                "Group {name} not found"
            )))
        })?;
    let id = group.id.ok_or_else(|| {
        PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
            "record missing id".into(),
        ))
    })?;
    let result = state
        .groups
        .update_group
        .execute(id, body.name, body.enabled, body.comment)
        .await?;
    Ok(Json(group_to_entry(&result)?))
}

/// Pi-hole v6 DELETE /api/groups/:name — delete group.
pub async fn delete_group(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, PiholeApiError> {
    let groups = state.groups.get_groups.get_all().await?;
    let group = groups
        .iter()
        .find(|g| g.name.as_ref() == name)
        .ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                "Group {name} not found"
            )))
        })?;
    let id = group.id.ok_or_else(|| {
        PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
            "record missing id".into(),
        ))
    })?;
    state.groups.delete_group.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Pi-hole v6 POST /api/groups:batchDelete — batch delete groups.
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    Json(body): Json<BatchDeleteRequest>,
) -> Result<StatusCode, PiholeApiError> {
    let groups = state.groups.get_groups.get_all().await?;
    for item in &body.items {
        if let Some(g) = groups.iter().find(|g| g.name.as_ref() == item.as_str()) {
            let id = g.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            state.groups.delete_group.execute(id).await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
