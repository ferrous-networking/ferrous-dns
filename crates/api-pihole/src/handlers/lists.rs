use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::{
    dto::domains::BatchDeleteRequest,
    dto::lists::{CreateListRequest, ListsResponse, PiholeListEntry},
    errors::PiholeApiError,
    state::PiholeAppState,
};

fn blocklist_to_entry(
    s: &ferrous_dns_domain::BlocklistSource,
) -> Result<PiholeListEntry, PiholeApiError> {
    Ok(PiholeListEntry {
        id: s.id.ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                "blocklist source missing id".into(),
            ))
        })?,
        address: s.url.as_ref().map(|u| u.to_string()).unwrap_or_default(),
        enabled: s.enabled,
        comment: s.comment.as_ref().map(|c| c.to_string()),
        r#type: 0,
        groups: s.group_ids.clone(),
        date_added: s.created_at.clone(),
        date_modified: s.updated_at.clone(),
        number: 0,
        status: if s.enabled { 1 } else { 0 },
    })
}

fn whitelist_to_entry(
    s: &ferrous_dns_domain::WhitelistSource,
) -> Result<PiholeListEntry, PiholeApiError> {
    Ok(PiholeListEntry {
        id: s.id.ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                "whitelist source missing id".into(),
            ))
        })?,
        address: s.url.as_ref().map(|u| u.to_string()).unwrap_or_default(),
        enabled: s.enabled,
        comment: s.comment.as_ref().map(|c| c.to_string()),
        r#type: 1,
        groups: s.group_ids.clone(),
        date_added: s.created_at.clone(),
        date_modified: s.updated_at.clone(),
        number: 0,
        status: if s.enabled { 1 } else { 0 },
    })
}

/// Pi-hole v6 GET /api/lists — list all adlists.
pub async fn list_all(
    State(state): State<PiholeAppState>,
) -> Result<Json<ListsResponse>, PiholeApiError> {
    let (blocklists, whitelists) = tokio::join!(
        state.lists.get_blocklist_sources.get_all(),
        state.lists.get_whitelist_sources.get_all(),
    );

    let mut lists: Vec<PiholeListEntry> = Vec::new();
    for s in blocklists? {
        lists.push(blocklist_to_entry(&s)?);
    }
    for s in whitelists? {
        lists.push(whitelist_to_entry(&s)?);
    }

    Ok(Json(ListsResponse { lists }))
}

/// Pi-hole v6 POST /api/lists — create adlist.
pub async fn create_list(
    State(state): State<PiholeAppState>,
    Json(body): Json<CreateListRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let list_type = body.r#type.unwrap_or(0);
    let group_ids = body.groups.unwrap_or_else(|| vec![1]);
    let enabled = body.enabled.unwrap_or(true);

    if list_type == 1 {
        let result = state
            .lists
            .create_whitelist_source
            .execute(
                body.address.clone(),
                Some(body.address),
                group_ids,
                body.comment,
                enabled,
            )
            .await?;
        Ok((StatusCode::CREATED, Json(whitelist_to_entry(&result)?)))
    } else {
        let result = state
            .lists
            .create_blocklist_source
            .execute(
                body.address.clone(),
                Some(body.address),
                group_ids,
                body.comment,
                enabled,
            )
            .await?;
        Ok((StatusCode::CREATED, Json(blocklist_to_entry(&result)?)))
    }
}

/// Pi-hole v6 GET /api/lists/:id — get by id.
pub async fn get_by_id(
    State(state): State<PiholeAppState>,
    Path(id): Path<i64>,
) -> Result<Json<PiholeListEntry>, PiholeApiError> {
    if let Some(s) = state.lists.get_blocklist_sources.get_by_id(id).await? {
        return Ok(Json(blocklist_to_entry(&s)?));
    }
    if let Some(s) = state.lists.get_whitelist_sources.get_by_id(id).await? {
        return Ok(Json(whitelist_to_entry(&s)?));
    }
    Err(PiholeApiError(ferrous_dns_domain::DomainError::NotFound(
        format!("List {id} not found"),
    )))
}

/// Pi-hole v6 PUT /api/lists/:id — update adlist.
pub async fn update_list(
    State(state): State<PiholeAppState>,
    Path(id): Path<i64>,
    Json(body): Json<CreateListRequest>,
) -> Result<Json<PiholeListEntry>, PiholeApiError> {
    let group_ids = body.groups;

    // Try blocklist first, then whitelist.
    if let Some(_existing) = state.lists.get_blocklist_sources.get_by_id(id).await? {
        let result = state
            .lists
            .update_blocklist_source
            .execute(
                id,
                Some(body.address.clone()),
                Some(Some(body.address)),
                group_ids,
                body.comment,
                body.enabled,
            )
            .await?;
        return Ok(Json(blocklist_to_entry(&result)?));
    }

    if let Some(_existing) = state.lists.get_whitelist_sources.get_by_id(id).await? {
        let result = state
            .lists
            .update_whitelist_source
            .execute(
                id,
                Some(body.address.clone()),
                Some(Some(body.address)),
                group_ids,
                body.comment,
                body.enabled,
            )
            .await?;
        return Ok(Json(whitelist_to_entry(&result)?));
    }

    Err(PiholeApiError(ferrous_dns_domain::DomainError::NotFound(
        format!("List {id} not found"),
    )))
}

/// Pi-hole v6 DELETE /api/lists/:id — delete adlist.
pub async fn delete_list(
    State(state): State<PiholeAppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, PiholeApiError> {
    if state
        .lists
        .get_blocklist_sources
        .get_by_id(id)
        .await?
        .is_some()
    {
        state.lists.delete_blocklist_source.execute(id).await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    if state
        .lists
        .get_whitelist_sources
        .get_by_id(id)
        .await?
        .is_some()
    {
        state.lists.delete_whitelist_source.execute(id).await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    Err(PiholeApiError(ferrous_dns_domain::DomainError::NotFound(
        format!("List {id} not found"),
    )))
}

/// Pi-hole v6 POST /api/lists:batchDelete — batch delete.
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    Json(body): Json<BatchDeleteRequest>,
) -> Result<StatusCode, PiholeApiError> {
    for item in &body.items {
        if let Ok(id) = item.parse::<i64>() {
            if state
                .lists
                .get_blocklist_sources
                .get_by_id(id)
                .await?
                .is_some()
            {
                state.lists.delete_blocklist_source.execute(id).await?;
            } else if state
                .lists
                .get_whitelist_sources
                .get_by_id(id)
                .await?
                .is_some()
            {
                state.lists.delete_whitelist_source.execute(id).await?;
            }
        }
    }

    Ok(StatusCode::NO_CONTENT)
}
