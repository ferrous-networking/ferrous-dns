use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use ferrous_dns_domain::{BlocklistSource, DomainError, WhitelistSource};

use crate::{
    dto::lists::{
        CreateListRequest, ListBatchDeleteItem, ListType, ListTypeQuery, ListsResponse,
        PiholeListEntry, UpdateListRequest,
    },
    errors::PiholeApiError,
    extract::PiholeJson,
    handlers::require_id,
    state::PiholeAppState,
};

/// The `{list}` path segment. Pi-hole addresses a list by its URL; a bare
/// number is the database id, which is only unique within one list type.
#[derive(Clone, Copy)]
enum ListKey<'a> {
    Id(i64),
    Address(&'a str),
}

impl<'a> ListKey<'a> {
    fn parse(segment: &'a str) -> Self {
        segment.parse().map_or(Self::Address(segment), Self::Id)
    }
}

fn parse_type(raw: Option<&str>) -> Result<Option<ListType>, DomainError> {
    raw.map(str::parse).transpose()
}

/// Ids and addresses may repeat across list types, so writes must name one.
fn require_type(raw: Option<&str>) -> Result<ListType, DomainError> {
    parse_type(raw)?.ok_or_else(|| {
        DomainError::InvalidInput("Specify the list type (?type=allow or ?type=block)".to_string())
    })
}

fn list_not_found(list: &str) -> PiholeApiError {
    DomainError::NotFound(format!("List {list} not found")).into()
}

fn blocklist_to_entry(s: &BlocklistSource) -> Result<PiholeListEntry, DomainError> {
    Ok(PiholeListEntry {
        id: require_id(s.id, "blocklist source")?,
        address: s.url.as_ref().map(|u| u.to_string()).unwrap_or_default(),
        enabled: s.enabled,
        comment: s.comment.as_ref().map(|c| c.to_string()),
        r#type: ListType::Block,
        groups: s.group_ids.clone(),
        date_added: s.created_at.clone(),
        date_modified: s.updated_at.clone(),
        number: 0,
        status: if s.enabled { 1 } else { 0 },
    })
}

fn whitelist_to_entry(s: &WhitelistSource) -> Result<PiholeListEntry, DomainError> {
    Ok(PiholeListEntry {
        id: require_id(s.id, "whitelist source")?,
        address: s.url.as_ref().map(|u| u.to_string()).unwrap_or_default(),
        enabled: s.enabled,
        comment: s.comment.as_ref().map(|c| c.to_string()),
        r#type: ListType::Allow,
        groups: s.group_ids.clone(),
        date_added: s.created_at.clone(),
        date_modified: s.updated_at.clone(),
        number: 0,
        status: if s.enabled { 1 } else { 0 },
    })
}

async fn find_blocklists(
    state: &PiholeAppState,
    key: ListKey<'_>,
) -> Result<Vec<BlocklistSource>, DomainError> {
    let sources = &state.lists.get_blocklist_sources;
    match key {
        ListKey::Id(id) => Ok(sources.get_by_id(id).await?.into_iter().collect()),
        ListKey::Address(address) => Ok(sources
            .get_all()
            .await?
            .into_iter()
            .filter(|s| s.url.as_deref() == Some(address))
            .collect()),
    }
}

async fn find_whitelists(
    state: &PiholeAppState,
    key: ListKey<'_>,
) -> Result<Vec<WhitelistSource>, DomainError> {
    let sources = &state.lists.get_whitelist_sources;
    match key {
        ListKey::Id(id) => Ok(sources.get_by_id(id).await?.into_iter().collect()),
        ListKey::Address(address) => Ok(sources
            .get_all()
            .await?
            .into_iter()
            .filter(|s| s.url.as_deref() == Some(address))
            .collect()),
    }
}

/// Entries of the given type (both when `None`), narrowed to `key` if given.
async fn read_entries(
    state: &PiholeAppState,
    only: Option<ListType>,
    key: Option<ListKey<'_>>,
) -> Result<Vec<PiholeListEntry>, DomainError> {
    let (block, allow) = match only {
        None => (true, true),
        Some(ListType::Block) => (true, false),
        Some(ListType::Allow) => (false, true),
    };

    let mut lists = Vec::new();
    if block {
        let sources = match key {
            Some(key) => find_blocklists(state, key).await?,
            None => state.lists.get_blocklist_sources.get_all().await?,
        };
        for s in &sources {
            lists.push(blocklist_to_entry(s)?);
        }
    }
    if allow {
        let sources = match key {
            Some(key) => find_whitelists(state, key).await?,
            None => state.lists.get_whitelist_sources.get_all().await?,
        };
        for s in &sources {
            lists.push(whitelist_to_entry(s)?);
        }
    }
    Ok(lists)
}

/// Deletes every list of `list_type` matching `key`; returns how many.
async fn delete_matching(
    state: &PiholeAppState,
    key: ListKey<'_>,
    list_type: ListType,
) -> Result<usize, DomainError> {
    let mut deleted = 0;
    match list_type {
        ListType::Block => {
            for s in find_blocklists(state, key).await? {
                let id = require_id(s.id, "blocklist source")?;
                state.lists.delete_blocklist_source.execute(id).await?;
                deleted += 1;
            }
        }
        ListType::Allow => {
            for s in find_whitelists(state, key).await? {
                let id = require_id(s.id, "whitelist source")?;
                state.lists.delete_whitelist_source.execute(id).await?;
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

/// Pi-hole v6 GET /api/lists — list all adlists.
#[utoipa::path(
    get,
    path = "/lists",
    tag = "pihole:lists",
    params(
        ("type" = Option<String>, Query, description = "Only lists of this type: allow or block")
    ),
    responses(
        (status = 200, description = "Adlists (blocklists and allowlists)", body = ListsResponse),
        (status = 400, description = "Unknown list type")
    ),
    security(("session_id" = []))
)]
pub async fn list_all(
    State(state): State<PiholeAppState>,
    Query(query): Query<ListTypeQuery>,
) -> Result<Json<ListsResponse>, PiholeApiError> {
    let only = parse_type(query.r#type.as_deref())?;
    let lists = read_entries(&state, only, None).await?;
    Ok(Json(ListsResponse { lists }))
}

/// Pi-hole v6 POST /api/lists?type=allow|block — create adlist.
#[utoipa::path(
    post,
    path = "/lists",
    tag = "pihole:lists",
    params(
        ("type" = String, Query, description = "List type: allow or block")
    ),
    request_body = CreateListRequest,
    responses(
        (status = 201, description = "List created", body = PiholeListEntry),
        (status = 400, description = "Missing or unknown list type")
    ),
    security(("session_id" = []))
)]
pub async fn create_list(
    State(state): State<PiholeAppState>,
    Query(query): Query<ListTypeQuery>,
    PiholeJson(body): PiholeJson<CreateListRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let list_type = require_type(query.r#type.as_deref())?;
    let group_ids = body.groups.unwrap_or_else(|| vec![1]);
    let enabled = body.enabled.unwrap_or(true);

    let entry = match list_type {
        ListType::Allow => whitelist_to_entry(
            &state
                .lists
                .create_whitelist_source
                .execute(
                    body.address.clone(),
                    Some(body.address),
                    group_ids,
                    body.comment,
                    enabled,
                )
                .await?,
        )?,
        ListType::Block => blocklist_to_entry(
            &state
                .lists
                .create_blocklist_source
                .execute(
                    body.address.clone(),
                    Some(body.address),
                    group_ids,
                    body.comment,
                    enabled,
                )
                .await?,
        )?,
    };
    Ok((StatusCode::CREATED, Json(entry)))
}

/// Pi-hole v6 GET /api/lists/{list} — lists with this address (or id).
#[utoipa::path(
    get,
    path = "/lists/{list}",
    tag = "pihole:lists",
    params(
        ("list" = String, Path, description = "List address (URL-encoded) or numeric id"),
        ("type" = Option<String>, Query, description = "Only lists of this type: allow or block")
    ),
    responses(
        (status = 200, description = "Matching lists", body = ListsResponse),
        (status = 400, description = "Unknown list type"),
        (status = 404, description = "List not found")
    ),
    security(("session_id" = []))
)]
pub async fn get_list(
    State(state): State<PiholeAppState>,
    Path(list): Path<String>,
    Query(query): Query<ListTypeQuery>,
) -> Result<Json<ListsResponse>, PiholeApiError> {
    let only = parse_type(query.r#type.as_deref())?;
    let lists = read_entries(&state, only, Some(ListKey::parse(&list))).await?;
    if lists.is_empty() {
        return Err(list_not_found(&list));
    }
    Ok(Json(ListsResponse { lists }))
}

/// Pi-hole v6 PUT /api/lists/{list}?type=allow|block — update adlist.
#[utoipa::path(
    put,
    path = "/lists/{list}",
    tag = "pihole:lists",
    params(
        ("list" = String, Path, description = "List address (URL-encoded) or numeric id"),
        ("type" = String, Query, description = "List type: allow or block")
    ),
    request_body = UpdateListRequest,
    responses(
        (status = 200, description = "Updated lists", body = ListsResponse),
        (status = 400, description = "Missing or unknown list type"),
        (status = 404, description = "List not found")
    ),
    security(("session_id" = []))
)]
pub async fn update_list(
    State(state): State<PiholeAppState>,
    Path(list): Path<String>,
    Query(query): Query<ListTypeQuery>,
    PiholeJson(body): PiholeJson<UpdateListRequest>,
) -> Result<Json<ListsResponse>, PiholeApiError> {
    let list_type = require_type(query.r#type.as_deref())?;
    let key = ListKey::parse(&list);

    let mut lists = Vec::new();
    match list_type {
        ListType::Block => {
            for s in find_blocklists(&state, key).await? {
                let id = require_id(s.id, "blocklist source")?;
                let updated = state
                    .lists
                    .update_blocklist_source
                    .execute(
                        id,
                        None,
                        None,
                        body.groups.clone(),
                        body.comment.clone(),
                        body.enabled,
                    )
                    .await?;
                lists.push(blocklist_to_entry(&updated)?);
            }
        }
        ListType::Allow => {
            for s in find_whitelists(&state, key).await? {
                let id = require_id(s.id, "whitelist source")?;
                let updated = state
                    .lists
                    .update_whitelist_source
                    .execute(
                        id,
                        None,
                        None,
                        body.groups.clone(),
                        body.comment.clone(),
                        body.enabled,
                    )
                    .await?;
                lists.push(whitelist_to_entry(&updated)?);
            }
        }
    }

    if lists.is_empty() {
        return Err(list_not_found(&list));
    }
    Ok(Json(ListsResponse { lists }))
}

/// Pi-hole v6 DELETE /api/lists/{list}?type=allow|block — delete adlist.
#[utoipa::path(
    delete,
    path = "/lists/{list}",
    tag = "pihole:lists",
    params(
        ("list" = String, Path, description = "List address (URL-encoded) or numeric id"),
        ("type" = String, Query, description = "List type: allow or block")
    ),
    responses(
        (status = 204, description = "List deleted"),
        (status = 400, description = "Missing or unknown list type"),
        (status = 404, description = "List not found")
    ),
    security(("session_id" = []))
)]
pub async fn delete_list(
    State(state): State<PiholeAppState>,
    Path(list): Path<String>,
    Query(query): Query<ListTypeQuery>,
) -> Result<StatusCode, PiholeApiError> {
    let list_type = require_type(query.r#type.as_deref())?;
    if delete_matching(&state, ListKey::parse(&list), list_type).await? == 0 {
        return Err(list_not_found(&list));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Pi-hole v6 POST /api/lists:batchDelete — body `[{item, type}]`.
#[utoipa::path(
    post,
    path = "/lists:batchDelete",
    tag = "pihole:lists",
    request_body = Vec<ListBatchDeleteItem>,
    responses(
        (status = 204, description = "Batch delete completed"),
        (status = 400, description = "An item has an unknown list type")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<Vec<ListBatchDeleteItem>>,
) -> Result<StatusCode, PiholeApiError> {
    // Parse every item first so a bad type deletes nothing.
    let targets = body
        .iter()
        .map(|i| Ok((ListKey::parse(&i.item), i.r#type.parse::<ListType>()?)))
        .collect::<Result<Vec<_>, DomainError>>()?;

    for (key, list_type) in targets {
        delete_matching(&state, key, list_type).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}
