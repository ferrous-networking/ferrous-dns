use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ferrous_dns_domain::{BlocklistSource, DomainError, WhitelistSource};

use crate::{
    crud::{
        delete_reply, from_ftl_group_ids, record, reject_unsafe_item, reply_comment,
        request_comment, require_items, to_ftl_group_id, unix_seconds, write_status, CrudError,
        DEFAULT_GROUP_ID,
    },
    dto::crud::{BatchDeleteItem, Processed},
    dto::lists::{
        CreateListRequest, ListType, ListTypeQuery, ListsResponse, ListsWriteResponse,
        PiholeListEntry, UpdateListRequest,
    },
    extract::{PiholeJson, UriItem},
    handlers::require_id,
    state::PiholeAppState,
};

/// FTL's status of a list whose download succeeded. Ferrous records only
/// successful downloads, so FTL's codes for a failed one never appear.
const STATUS_DOWNLOADED: i64 = 1;

/// FTL's status of a list gravity has not processed.
const STATUS_UNKNOWN: i64 = 0;

/// The `{list}` path segment. Pi-hole addresses a list by its URL. A bare
/// number is a Ferrous extension naming the database id, which is only
/// unique within one list type; list URLs start with `http`, so the two
/// never collide.
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

/// `?type=`, which FTL takes as absent when empty.
fn parse_type(raw: Option<&str>) -> Result<Option<ListType>, CrudError> {
    let Some(raw) = raw.filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    ListType::parse(raw).map(Some).ok_or_else(|| {
        CrudError::bad_request(
            "Invalid request: Invalid type parameter (should be either \"allow\" or \"block\")",
            Some(format!("type={raw}")),
        )
    })
}

/// Addresses and ids may repeat across list types, so writes must name one.
fn require_type(raw: Option<&str>) -> Result<ListType, CrudError> {
    parse_type(raw)?.ok_or_else(|| {
        CrudError::bad_request(
            "Invalid request: Specify type parameter (should be either \"allow\" or \"block\")",
            None,
        )
    })
}

/// A list of either table.
struct StoredList {
    list_type: ListType,
    id: i64,
    address: Option<Arc<str>>,
    comment: Option<Arc<str>>,
    enabled: bool,
    group_ids: Vec<i64>,
    created_at: Option<String>,
    updated_at: Option<String>,
    last_synced_at: Option<String>,
}

impl StoredList {
    fn from_blocklist(s: BlocklistSource) -> Result<Self, DomainError> {
        Ok(Self {
            list_type: ListType::Block,
            id: require_id(s.id, "blocklist source")?,
            address: s.url,
            comment: s.comment,
            enabled: s.enabled,
            group_ids: s.group_ids,
            created_at: s.created_at,
            updated_at: s.updated_at,
            last_synced_at: s.last_synced_at,
        })
    }

    fn from_whitelist(s: WhitelistSource) -> Result<Self, DomainError> {
        Ok(Self {
            list_type: ListType::Allow,
            id: require_id(s.id, "whitelist source")?,
            address: s.url,
            comment: s.comment,
            enabled: s.enabled,
            group_ids: s.group_ids,
            created_at: s.created_at,
            updated_at: s.updated_at,
            last_synced_at: s.last_synced_at,
        })
    }

    fn matches(&self, key: ListKey<'_>) -> bool {
        match key {
            ListKey::Id(id) => self.id == id,
            ListKey::Address(address) => self.address.as_deref() == Some(address),
        }
    }

    fn to_entry(&self) -> PiholeListEntry {
        PiholeListEntry {
            address: self.address.as_deref().unwrap_or_default().to_string(),
            comment: reply_comment(self.comment.as_ref()),
            groups: self
                .group_ids
                .iter()
                .copied()
                .map(to_ftl_group_id)
                .collect(),
            enabled: self.enabled,
            id: self.id,
            date_added: unix_seconds(self.created_at.as_deref()),
            date_modified: unix_seconds(self.updated_at.as_deref()),
            r#type: self.list_type,
            date_updated: unix_seconds(self.last_synced_at.as_deref()),
            number: 0,
            invalid_domains: 0,
            abp_entries: 0,
            status: if self.last_synced_at.is_some() {
                STATUS_DOWNLOADED
            } else {
                STATUS_UNKNOWN
            },
        }
    }
}

/// Lists of the given type (both when `None`), blocklists first, each in id
/// order like FTL's table.
async fn stored_lists(
    state: &PiholeAppState,
    only: Option<ListType>,
) -> Result<Vec<StoredList>, DomainError> {
    let mut lists = Vec::new();
    if only != Some(ListType::Allow) {
        let mut block = state
            .lists
            .get_blocklist_sources
            .get_all()
            .await?
            .into_iter()
            .map(StoredList::from_blocklist)
            .collect::<Result<Vec<_>, _>>()?;
        block.sort_by_key(|l| l.id);
        lists.append(&mut block);
    }
    if only != Some(ListType::Block) {
        let mut allow = state
            .lists
            .get_whitelist_sources
            .get_all()
            .await?
            .into_iter()
            .map(StoredList::from_whitelist)
            .collect::<Result<Vec<_>, _>>()?;
        allow.sort_by_key(|l| l.id);
        lists.append(&mut allow);
    }
    Ok(lists)
}

/// The lists of the given type that `key` names, or all of them.
async fn find_lists(
    state: &PiholeAppState,
    only: Option<ListType>,
    key: Option<ListKey<'_>>,
) -> Result<Vec<StoredList>, DomainError> {
    let mut lists = stored_lists(state, only).await?;
    if let Some(key) = key {
        lists.retain(|l| l.matches(key));
    }
    Ok(lists)
}

async fn read_lists(
    state: &PiholeAppState,
    only: Option<ListType>,
    key: Option<ListKey<'_>>,
) -> Result<Vec<PiholeListEntry>, DomainError> {
    Ok(find_lists(state, only, key)
        .await?
        .iter()
        .map(StoredList::to_entry)
        .collect())
}

async fn add_list(
    state: &PiholeAppState,
    list_type: ListType,
    address: &str,
    group_ids: Vec<i64>,
    comment: Option<String>,
    enabled: bool,
) -> Result<(), DomainError> {
    let (name, url) = (address.to_string(), Some(address.to_string()));
    match list_type {
        ListType::Block => state
            .lists
            .create_blocklist_source
            .execute(name, url, group_ids, comment, enabled)
            .await
            .map(drop),
        ListType::Allow => state
            .lists
            .create_whitelist_source
            .execute(name, url, group_ids, comment, enabled)
            .await
            .map(drop),
    }
}

/// Rewrites `list`. An empty comment clears it, as the repository keeps a
/// comment it is not given.
async fn rewrite_list(
    state: &PiholeAppState,
    list: &StoredList,
    group_ids: Option<Vec<i64>>,
    comment: Option<String>,
    enabled: bool,
) -> Result<(), DomainError> {
    let comment = Some(comment.unwrap_or_default());
    match list.list_type {
        ListType::Block => state
            .lists
            .update_blocklist_source
            .execute(list.id, None, None, group_ids, comment, Some(enabled))
            .await
            .map(drop),
        ListType::Allow => state
            .lists
            .update_whitelist_source
            .execute(list.id, None, None, group_ids, comment, Some(enabled))
            .await
            .map(drop),
    }
}

/// Writes a PUT as gravity-db.c's upsert does: the list is replaced (an
/// omitted comment is cleared and `enabled` defaults to true) and its groups
/// only when given, or it is created when missing.
async fn replace_list(
    state: &PiholeAppState,
    list_type: ListType,
    key: ListKey<'_>,
    body: UpdateListRequest,
) -> Result<(), DomainError> {
    let group_ids = body.groups.map(from_ftl_group_ids);
    let comment = request_comment(body.comment);
    let enabled = body.enabled.unwrap_or(true);

    let existing = find_lists(state, Some(list_type), Some(key)).await?;
    if existing.is_empty() {
        return match key {
            ListKey::Address(address) => {
                let group_ids = group_ids.unwrap_or_else(|| vec![DEFAULT_GROUP_ID]);
                add_list(state, list_type, address, group_ids, comment, enabled).await
            }
            ListKey::Id(id) => Err(DomainError::NotFound(format!("List {id} not found"))),
        };
    }
    for list in &existing {
        rewrite_list(state, list, group_ids.clone(), comment.clone(), enabled).await?;
    }
    Ok(())
}

/// Deletes every list each `(key, type)` target names; returns how many.
async fn delete_lists(
    state: &PiholeAppState,
    targets: &[(ListKey<'_>, ListType)],
) -> Result<usize, DomainError> {
    let mut deleted = 0;
    for list in stored_lists(state, None).await? {
        let targeted = targets
            .iter()
            .any(|&(key, list_type)| list.list_type == list_type && list.matches(key));
        if !targeted {
            continue;
        }
        match list.list_type {
            ListType::Block => state.lists.delete_blocklist_source.execute(list.id).await?,
            ListType::Allow => state.lists.delete_whitelist_source.execute(list.id).await?,
        }
        deleted += 1;
    }
    Ok(deleted)
}

fn write_reply(status: StatusCode, lists: Vec<PiholeListEntry>, processed: Processed) -> Response {
    (status, Json(ListsWriteResponse { lists, processed })).into_response()
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
) -> Result<Json<ListsResponse>, CrudError> {
    let only = parse_type(query.r#type.as_deref())?;
    let lists = read_lists(&state, only, None).await?;
    Ok(Json(ListsResponse { lists }))
}

/// Pi-hole v6 POST /api/lists?type=allow|block — add one list or several.
#[utoipa::path(
    post,
    path = "/lists",
    tag = "pihole:lists",
    params(
        ("type" = String, Query, description = "List type: allow or block")
    ),
    request_body = CreateListRequest,
    responses(
        (status = 201, description = "The last list as stored, and what was processed", body = ListsWriteResponse),
        (status = 400, description = "Missing or unknown list type, no address, or every list failed")
    ),
    security(("session_id" = []))
)]
pub async fn create_list(
    State(state): State<PiholeAppState>,
    Query(query): Query<ListTypeQuery>,
    PiholeJson(body): PiholeJson<CreateListRequest>,
) -> Result<Response, CrudError> {
    let list_type = require_type(query.r#type.as_deref())?;
    let addresses = require_items(
        body.address,
        "Invalid request: No valid \"address\" in payload (must be either string or array)",
    )?;
    for address in &addresses {
        reject_unsafe_item(address, false)?;
    }
    let group_ids = body
        .groups
        .map_or_else(|| vec![DEFAULT_GROUP_ID], from_ftl_group_ids);
    let comment = request_comment(body.comment);
    let enabled = body.enabled.unwrap_or(true);

    // FTL keeps one list per address and type.
    let mut present: HashSet<String> = stored_lists(&state, Some(list_type))
        .await?
        .into_iter()
        .filter_map(|l| l.address.map(|a| a.to_string()))
        .collect();
    let mut processed = Processed::default();
    for address in &addresses {
        let result = if present.contains(address) {
            Err(DomainError::AlreadyExists(address.clone()))
        } else {
            add_list(
                &state,
                list_type,
                address,
                group_ids.clone(),
                comment.clone(),
                enabled,
            )
            .await
        };
        if result.is_ok() {
            present.insert(address.clone());
        }
        record(&mut processed, address, result)?;
    }

    let status = write_status(&processed, StatusCode::CREATED)?;
    let last = addresses.last().map(String::as_str).unwrap_or_default();
    let lists = read_lists(&state, Some(list_type), Some(ListKey::Address(last))).await?;
    Ok(write_reply(status, lists, processed))
}

/// Pi-hole v6 GET /api/lists/{list} — lists with this address (or id).
#[utoipa::path(
    get,
    path = "/lists/{list}",
    tag = "pihole:lists",
    params(
        ("list" = String, Path, description = "List address (URL-encoded or not) or numeric id"),
        ("type" = Option<String>, Query, description = "Only lists of this type: allow or block")
    ),
    responses(
        (status = 200, description = "Matching lists, possibly none", body = ListsResponse),
        (status = 400, description = "Unknown list type")
    ),
    security(("session_id" = []))
)]
pub async fn get_list(
    State(state): State<PiholeAppState>,
    UriItem(list): UriItem,
    Query(query): Query<ListTypeQuery>,
) -> Result<Json<ListsResponse>, CrudError> {
    let only = parse_type(query.r#type.as_deref())?;
    let lists = read_lists(&state, only, Some(ListKey::parse(&list))).await?;
    Ok(Json(ListsResponse { lists }))
}

/// Pi-hole v6 PUT /api/lists/{list}?type=allow|block — replace or create a list.
#[utoipa::path(
    put,
    path = "/lists/{list}",
    tag = "pihole:lists",
    params(
        ("list" = String, Path, description = "List address (URL-encoded or not) or numeric id"),
        ("type" = String, Query, description = "List type: allow or block")
    ),
    request_body = UpdateListRequest,
    responses(
        (status = 200, description = "The list as stored, and what was processed", body = ListsWriteResponse),
        (status = 400, description = "Missing or unknown list type, or the write failed")
    ),
    security(("session_id" = []))
)]
pub async fn update_list(
    State(state): State<PiholeAppState>,
    UriItem(list): UriItem,
    Query(query): Query<ListTypeQuery>,
    PiholeJson(body): PiholeJson<UpdateListRequest>,
) -> Result<Response, CrudError> {
    let list_type = require_type(query.r#type.as_deref())?;
    reject_unsafe_item(&list, false)?;
    let key = ListKey::parse(&list);

    let mut processed = Processed::default();
    let result = replace_list(&state, list_type, key, body).await;
    record(&mut processed, &list, result)?;

    let status = write_status(&processed, StatusCode::OK)?;
    let lists = read_lists(&state, Some(list_type), Some(key)).await?;
    Ok(write_reply(status, lists, processed))
}

/// Pi-hole v6 DELETE /api/lists/{list}?type=allow|block — delete adlist.
#[utoipa::path(
    delete,
    path = "/lists/{list}",
    tag = "pihole:lists",
    params(
        ("list" = String, Path, description = "List address (URL-encoded or not) or numeric id"),
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
    UriItem(list): UriItem,
    Query(query): Query<ListTypeQuery>,
) -> Result<Response, CrudError> {
    let list_type = require_type(query.r#type.as_deref())?;
    let deleted = delete_lists(&state, &[(ListKey::parse(&list), list_type)])
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}

/// Pi-hole v6 POST /api/lists:batchDelete — body `[{item, type}]`. An item
/// without a known type matches nothing, as in gravity-db.c; `?type=`
/// overrides every item's type.
#[utoipa::path(
    post,
    path = "/lists:batchDelete",
    tag = "pihole:lists",
    params(
        ("type" = Option<String>, Query, description = "List type for every item: allow or block")
    ),
    request_body = Vec<BatchDeleteItem>,
    responses(
        (status = 204, description = "Lists deleted"),
        (status = 400, description = "Unknown list type in the query"),
        (status = 404, description = "Nothing matched")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    Query(query): Query<ListTypeQuery>,
    PiholeJson(body): PiholeJson<Vec<BatchDeleteItem>>,
) -> Result<Response, CrudError> {
    let forced = parse_type(query.r#type.as_deref())?;
    let targets: Vec<(ListKey<'_>, ListType)> = body
        .iter()
        .filter_map(|entry| {
            let list_type =
                forced.or_else(|| entry.item_type.as_deref().and_then(ListType::parse))?;
            Some((ListKey::parse(&entry.item), list_type))
        })
        .collect();

    let deleted = delete_lists(&state, &targets)
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}
