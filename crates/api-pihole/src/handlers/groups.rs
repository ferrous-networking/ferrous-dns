use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ferrous_dns_domain::{DomainError, Group};

use crate::{
    crud::{
        delete_reply, record, reject_unsafe_item, reply_comment, request_comment, require_items,
        to_ftl_group_id, unix_seconds, write_status, CrudError,
    },
    dto::crud::{BatchDeleteItem, Processed},
    dto::groups::{
        CreateGroupRequest, GroupsResponse, GroupsWriteResponse, PiholeGroupEntry,
        UpdateGroupRequest,
    },
    extract::PiholeJson,
    handlers::require_id,
    state::PiholeAppState,
};

fn group_to_entry(g: &Group) -> Result<PiholeGroupEntry, DomainError> {
    Ok(PiholeGroupEntry {
        name: g.name.to_string(),
        comment: reply_comment(g.comment.as_ref()),
        enabled: g.enabled,
        id: to_ftl_group_id(require_id(g.id, "group")?),
        date_added: unix_seconds(g.created_at.as_deref()),
        date_modified: unix_seconds(g.updated_at.as_deref()),
    })
}

/// The groups named `name`, or all of them for an empty name, in id order
/// like FTL's table.
async fn read_groups(
    state: &PiholeAppState,
    name: &str,
) -> Result<Vec<PiholeGroupEntry>, DomainError> {
    let mut groups = state.groups.get_groups.get_all().await?;
    groups.sort_by_key(|g| g.id);
    groups
        .iter()
        .filter(|g| name.is_empty() || g.name.as_ref() == name)
        .map(group_to_entry)
        .collect()
}

async fn find_group(state: &PiholeAppState, name: &str) -> Result<Option<Group>, DomainError> {
    Ok(state
        .groups
        .get_groups
        .get_all()
        .await?
        .into_iter()
        .find(|g| g.name.as_ref() == name))
}

/// Writes a PUT as gravity-db.c does: a `name` in the body renames the group
/// (and writes nothing when it does not exist); otherwise the group is
/// replaced, or created when missing.
async fn replace_group(
    state: &PiholeAppState,
    name: &str,
    body: UpdateGroupRequest,
) -> Result<(), DomainError> {
    let rename = body.name.filter(|n| !n.is_empty());
    let comment = request_comment(body.comment);
    let enabled = body.enabled.unwrap_or(true);

    let Some(existing) = find_group(state, name).await? else {
        if rename.is_some() {
            return Ok(());
        }
        return state
            .groups
            .create_group
            .execute(name.to_string(), comment, enabled)
            .await
            .map(drop);
    };
    let id = require_id(existing.id, "group")?;
    // The repository keeps a comment it is not given, so an empty one
    // clears it; replies send it back as null.
    state
        .groups
        .update_group
        .execute(id, rename, Some(enabled), Some(comment.unwrap_or_default()))
        .await
        .map(drop)
}

/// Deletes the groups named in `names`, returning how many went.
async fn delete_groups(state: &PiholeAppState, names: &[String]) -> Result<usize, DomainError> {
    let groups = state.groups.get_groups.get_all().await?;
    let mut deleted = 0;
    for group in groups
        .iter()
        .filter(|g| names.iter().any(|n| g.name.as_ref() == n.as_str()))
    {
        let id = require_id(group.id, "group")?;
        state.groups.delete_group.execute(id).await?;
        deleted += 1;
    }
    Ok(deleted)
}

fn write_reply(
    status: StatusCode,
    groups: Vec<PiholeGroupEntry>,
    processed: Processed,
) -> Response {
    (status, Json(GroupsWriteResponse { groups, processed })).into_response()
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
) -> Result<Json<GroupsResponse>, CrudError> {
    let groups = read_groups(&state, "").await?;
    Ok(Json(GroupsResponse { groups }))
}

/// Pi-hole v6 POST /api/groups — add one group or several.
#[utoipa::path(
    post,
    path = "/groups",
    tag = "pihole:groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "The last group as stored, and what was processed", body = GroupsWriteResponse),
        (status = 400, description = "Bad name, or every group failed")
    ),
    security(("session_id" = []))
)]
pub async fn create_group(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<CreateGroupRequest>,
) -> Result<Response, CrudError> {
    let names = require_items(
        body.name,
        "Invalid request: No valid \"name\" in payload (must be either string or array)",
    )?;
    for name in &names {
        reject_unsafe_item(name, true)?;
    }
    let comment = request_comment(body.comment);
    let enabled = body.enabled.unwrap_or(true);

    let mut processed = Processed::default();
    for name in &names {
        let result = state
            .groups
            .create_group
            .execute(name.clone(), comment.clone(), enabled)
            .await
            .map(drop);
        record(&mut processed, name, result)?;
    }

    let status = write_status(&processed, StatusCode::CREATED)?;
    let last = names.last().map(String::as_str).unwrap_or_default();
    let groups = read_groups(&state, last).await?;
    Ok(write_reply(status, groups, processed))
}

/// Pi-hole v6 GET /api/groups/:name — the group, if it exists.
#[utoipa::path(
    get,
    path = "/groups/{name}",
    tag = "pihole:groups",
    params(
        ("name" = String, Path, description = "Group name")
    ),
    responses(
        (status = 200, description = "The group, or an empty list", body = GroupsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_by_name(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
) -> Result<Json<GroupsResponse>, CrudError> {
    let groups = read_groups(&state, &name).await?;
    Ok(Json(GroupsResponse { groups }))
}

/// Pi-hole v6 PUT /api/groups/:name — replace, create or rename a group.
#[utoipa::path(
    put,
    path = "/groups/{name}",
    tag = "pihole:groups",
    params(
        ("name" = String, Path, description = "Group name")
    ),
    request_body = UpdateGroupRequest,
    responses(
        (status = 200, description = "The group named in the URI, and what was processed", body = GroupsWriteResponse),
        (status = 400, description = "Bad name, or the write failed")
    ),
    security(("session_id" = []))
)]
pub async fn update_group(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
    PiholeJson(body): PiholeJson<UpdateGroupRequest>,
) -> Result<Response, CrudError> {
    reject_unsafe_item(&name, true)?;
    if let Some(rename) = &body.name {
        reject_unsafe_item(rename, true)?;
    }

    let mut processed = Processed::default();
    let result = replace_group(&state, &name, body).await;
    record(&mut processed, &name, result)?;

    let status = write_status(&processed, StatusCode::OK)?;
    // api_list_write reads back the URI name, so a renamed group is not in
    // the reply.
    let groups = read_groups(&state, &name).await?;
    Ok(write_reply(status, groups, processed))
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
        (status = 400, description = "The group cannot be deleted"),
        (status = 404, description = "Group not found")
    ),
    security(("session_id" = []))
)]
pub async fn delete_group(
    State(state): State<PiholeAppState>,
    Path(name): Path<String>,
) -> Result<Response, CrudError> {
    let deleted = delete_groups(&state, &[name])
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}

/// Pi-hole v6 POST /api/groups:batchDelete — delete `[{item}]`.
#[utoipa::path(
    post,
    path = "/groups:batchDelete",
    tag = "pihole:groups",
    request_body = Vec<BatchDeleteItem>,
    responses(
        (status = 204, description = "Groups deleted"),
        (status = 400, description = "A group cannot be deleted"),
        (status = 404, description = "Nothing matched")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<Vec<BatchDeleteItem>>,
) -> Result<Response, CrudError> {
    let names: Vec<String> = body.into_iter().map(|entry| entry.item).collect();
    let deleted = delete_groups(&state, &names)
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}
