use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ferrous_dns_application::ports::{ManagedDomainUpdate, RegexFilterUpdate};
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain, RegexFilter};

use crate::{
    crud::{
        delete_reply, first_group, record, reject_unsafe_item, reply_comment, request_comment,
        require_items, to_ftl_group_id, unix_seconds, write_status, CrudError, DEFAULT_GROUP_ID,
        LIST_IMPRECISE,
    },
    dto::crud::{BatchDeleteItem, Processed},
    dto::domains::{
        CreateDomainRequest, DomainsListResponse, DomainsWriteResponse, PiholeDomainEntry,
        UpdateDomainRequest,
    },
    extract::PiholeJson,
    handlers::require_id,
    state::PiholeAppState,
};

/// The `{kind}` path segment: exact entries are managed domains, regex
/// entries are regex filters.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DomainKind {
    Exact,
    Regex,
}

impl DomainKind {
    fn from_path(kind: &str) -> Option<Self> {
        match kind {
            "exact" => Some(Self::Exact),
            "regex" => Some(Self::Regex),
            _ => None,
        }
    }
}

fn action_from_path(domain_type: &str) -> Option<DomainAction> {
    match domain_type {
        "allow" => Some(DomainAction::Allow),
        "deny" => Some(DomainAction::Deny),
        _ => None,
    }
}

/// One of the four domain lists.
type DomainList = (DomainAction, DomainKind);

/// The lists a URI addresses; `None` spans both values.
#[derive(Clone, Copy, Default)]
struct ListSelector {
    action: Option<DomainAction>,
    kind: Option<DomainKind>,
}

impl ListSelector {
    fn of(list: DomainList) -> Self {
        Self {
            action: Some(list.0),
            kind: Some(list.1),
        }
    }

    fn list(self) -> Option<DomainList> {
        self.action.zip(self.kind)
    }

    fn selects(self, action: DomainAction, kind: DomainKind) -> bool {
        self.action.is_none_or(|a| a == action) && self.kind.is_none_or(|k| k == kind)
    }
}

/// Splits the segments after `/domains` into the lists they select and the
/// item, as api_list() matches its URI prefixes: `allow`/`deny`, then
/// `exact`/`regex`, or `exact`/`regex` alone; whatever is left is the item.
fn parse_segments(segments: &[&str]) -> (ListSelector, String) {
    let mut selector = ListSelector::default();
    let mut rest = segments;
    if let Some(action) = rest.first().and_then(|s| action_from_path(s)) {
        selector.action = Some(action);
        rest = &rest[1..];
    }
    if let Some(kind) = rest.first().and_then(|s| DomainKind::from_path(s)) {
        selector.kind = Some(kind);
        rest = &rest[1..];
    }
    (selector, rest.join("/"))
}

/// The one list a write addresses; anything vaguer is FTL's `uri_error`.
fn precise_list(domain_type: &str, kind: &str) -> Result<DomainList, CrudError> {
    let (selector, item) = parse_segments(&[domain_type, kind]);
    match selector.list() {
        Some(list) if item.is_empty() => Ok(list),
        _ => Err(CrudError::uri_error(LIST_IMPRECISE)),
    }
}

/// A `type`/`kind` pair from a body, matched without regard to case as
/// gravity-db.c does.
fn list_from_body(domain_type: &str, kind: &str) -> Option<DomainList> {
    let action = action_from_path(&domain_type.to_ascii_lowercase())?;
    let kind = DomainKind::from_path(&kind.to_ascii_lowercase())?;
    Some((action, kind))
}

/// Checks an item as api_list_write does before writing anything. Exact
/// domains are lowercased; Ferrous validates regexes when it stores them.
fn prepare_item(item: String, kind: DomainKind) -> Result<String, CrudError> {
    match kind {
        DomainKind::Exact => {
            reject_unsafe_item(&item, false)?;
            let item = item.to_lowercase();
            ManagedDomain::validate_domain(&item)
                .map_err(|_| CrudError::bad_request("Invalid domain", Some(item.clone())))?;
            Ok(item)
        }
        DomainKind::Regex => {
            reject_unsafe_item(&item, true)?;
            Ok(item)
        }
    }
}

pub(crate) fn managed_to_entry(d: &ManagedDomain) -> Result<PiholeDomainEntry, DomainError> {
    Ok(PiholeDomainEntry {
        domain: d.domain.to_string(),
        unicode: d.domain.to_string(),
        r#type: d.action.to_str(),
        kind: "exact",
        comment: reply_comment(d.comment.as_ref()),
        groups: vec![to_ftl_group_id(d.group_id)],
        enabled: d.enabled,
        id: require_id(d.id, "managed domain")?,
        date_added: unix_seconds(d.created_at.as_deref()),
        date_modified: unix_seconds(d.updated_at.as_deref()),
    })
}

pub(crate) fn regex_to_entry(r: &RegexFilter) -> Result<PiholeDomainEntry, DomainError> {
    Ok(PiholeDomainEntry {
        domain: r.pattern.to_string(),
        unicode: r.pattern.to_string(),
        r#type: r.action.to_str(),
        kind: "regex",
        comment: reply_comment(r.comment.as_ref()),
        groups: vec![to_ftl_group_id(r.group_id)],
        enabled: r.enabled,
        id: require_id(r.id, "regex filter")?,
        date_added: unix_seconds(r.created_at.as_deref()),
        date_modified: unix_seconds(r.updated_at.as_deref()),
    })
}

/// A stored entry of one of the four lists.
enum StoredEntry {
    Exact(ManagedDomain),
    Regex(RegexFilter),
}

impl StoredEntry {
    fn item(&self) -> &str {
        match self {
            Self::Exact(d) => &d.domain,
            Self::Regex(r) => &r.pattern,
        }
    }

    fn list(&self) -> DomainList {
        match self {
            Self::Exact(d) => (d.action, DomainKind::Exact),
            Self::Regex(r) => (r.action, DomainKind::Regex),
        }
    }

    fn group_id(&self) -> i64 {
        match self {
            Self::Exact(d) => d.group_id,
            Self::Regex(r) => r.group_id,
        }
    }

    fn to_entry(&self) -> Result<PiholeDomainEntry, DomainError> {
        match self {
            Self::Exact(d) => managed_to_entry(d),
            Self::Regex(r) => regex_to_entry(r),
        }
    }
}

/// The entries of the selected lists, filtered to `item` when it is set,
/// each list in insertion order like FTL's table.
async fn stored_entries(
    state: &PiholeAppState,
    selector: ListSelector,
    item: &str,
) -> Result<Vec<StoredEntry>, DomainError> {
    let mut entries = Vec::new();
    if selector.kind != Some(DomainKind::Regex) {
        let mut managed = state.blocking.get_managed_domains.get_all().await?;
        managed.sort_by_key(|d| d.id);
        entries.extend(managed.into_iter().map(StoredEntry::Exact));
    }
    if selector.kind != Some(DomainKind::Exact) {
        let mut regexes = state.blocking.get_regex_filters.get_all().await?;
        regexes.sort_by_key(|r| r.id);
        entries.extend(regexes.into_iter().map(StoredEntry::Regex));
    }
    entries.retain(|e| {
        let (action, kind) = e.list();
        selector.selects(action, kind) && (item.is_empty() || e.item() == item)
    });
    Ok(entries)
}

async fn read_domains(
    state: &PiholeAppState,
    selector: ListSelector,
    item: &str,
) -> Result<Vec<PiholeDomainEntry>, DomainError> {
    stored_entries(state, selector, item)
        .await?
        .iter()
        .map(StoredEntry::to_entry)
        .collect()
}

async fn find_entry(
    state: &PiholeAppState,
    item: &str,
    list: DomainList,
) -> Result<Option<StoredEntry>, DomainError> {
    Ok(stored_entries(state, ListSelector::of(list), item)
        .await?
        .into_iter()
        .next())
}

async fn create_entry(
    state: &PiholeAppState,
    item: &str,
    (action, kind): DomainList,
    group_id: i64,
    comment: Option<String>,
    enabled: bool,
) -> Result<(), DomainError> {
    let item = item.to_string();
    match kind {
        DomainKind::Exact => state
            .blocking
            .create_managed_domain
            .execute(item.clone(), item, action, group_id, comment, enabled)
            .await
            .map(drop),
        DomainKind::Regex => state
            .blocking
            .create_regex_filter
            .execute(item.clone(), item, action, group_id, comment, enabled)
            .await
            .map(drop),
    }
}

async fn delete_entry(state: &PiholeAppState, entry: &StoredEntry) -> Result<(), DomainError> {
    match entry {
        StoredEntry::Exact(d) => {
            let id = require_id(d.id, "managed domain")?;
            state.blocking.delete_managed_domain.execute(id).await
        }
        StoredEntry::Regex(r) => {
            let id = require_id(r.id, "regex filter")?;
            state.blocking.delete_regex_filter.execute(id).await
        }
    }
}

/// Deletes every entry matching one of `targets`, returning how many went.
async fn delete_entries(
    state: &PiholeAppState,
    targets: &[(String, DomainList)],
) -> Result<usize, DomainError> {
    let stored = stored_entries(state, ListSelector::default(), "").await?;
    let mut deleted = 0;
    for entry in stored.iter().filter(|e| {
        targets
            .iter()
            .any(|(item, list)| e.item() == item.as_str() && e.list() == *list)
    }) {
        delete_entry(state, entry).await?;
        deleted += 1;
    }
    Ok(deleted)
}

/// The list a PUT entry is in now, from the body's `type`/`kind`; without
/// them the entry stays in the URI's list. gravity-db.c binds this as
/// `:oldtype`.
fn previous_list(body: &UpdateDomainRequest, to: DomainList) -> Result<DomainList, DomainError> {
    let domain_type = body.domain_type.as_deref().filter(|t| !t.is_empty());
    let kind = body.kind.as_deref().filter(|k| !k.is_empty());
    match (domain_type, kind) {
        (None, None) => Ok(to),
        (None, Some(_)) => Err(DomainError::InvalidInput(
            "Field type missing from request".into(),
        )),
        (Some(_), None) => Err(DomainError::InvalidInput(
            "Field kind missing from request".into(),
        )),
        (Some(domain_type), Some(kind)) => list_from_body(domain_type, kind)
            .ok_or_else(|| DomainError::InvalidInput("Cannot interpret type/kind".into())),
    }
}

/// Writes a PUT: replaces the entry in its previous list and moves it to
/// `to`, or creates it in the previous list when it is missing, as the
/// UPSERT in gravity-db.c does.
async fn replace_entry(
    state: &PiholeAppState,
    item: &str,
    to: DomainList,
    body: &UpdateDomainRequest,
) -> Result<(), DomainError> {
    let from = previous_list(body, to)?;
    let comment = request_comment(body.comment.clone());
    let enabled = body.enabled.unwrap_or(true);
    let group_id = first_group(body.groups.as_deref());

    let Some(existing) = find_entry(state, item, from).await? else {
        let group_id = group_id.unwrap_or(DEFAULT_GROUP_ID);
        return create_entry(state, item, from, group_id, comment, enabled).await;
    };
    if from != to && find_entry(state, item, to).await?.is_some() {
        return Err(DomainError::AlreadyExists(item.to_string()));
    }

    match (&existing, to.1) {
        (StoredEntry::Exact(d), DomainKind::Exact) => {
            let id = require_id(d.id, "managed domain")?;
            let update = ManagedDomainUpdate {
                action: Some(to.0),
                group_id,
                comment: Some(comment),
                enabled: Some(enabled),
                ..Default::default()
            };
            state
                .blocking
                .update_managed_domain
                .execute(id, update)
                .await
                .map(drop)
        }
        (StoredEntry::Regex(r), DomainKind::Regex) => {
            let id = require_id(r.id, "regex filter")?;
            let update = RegexFilterUpdate {
                action: Some(to.0),
                group_id,
                comment: Some(comment),
                enabled: Some(enabled),
                ..Default::default()
            };
            state
                .blocking
                .update_regex_filter
                .execute(id, update)
                .await
                .map(drop)
        }
        // Exact and regex entries live in different tables, so a move
        // between them is a create followed by a delete.
        _ => {
            let group_id = group_id.unwrap_or(existing.group_id());
            create_entry(state, item, to, group_id, comment, enabled).await?;
            delete_entry(state, &existing).await
        }
    }
}

fn write_reply(
    status: StatusCode,
    domains: Vec<PiholeDomainEntry>,
    processed: Processed,
) -> Response {
    (status, Json(DomainsWriteResponse { domains, processed })).into_response()
}

/// Pi-hole v6 GET /api/domains — list all domains.
#[utoipa::path(
    get,
    path = "/domains",
    tag = "pihole:domains",
    responses(
        (status = 200, description = "All managed and regex domains", body = DomainsListResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_all(
    State(state): State<PiholeAppState>,
) -> Result<Json<DomainsListResponse>, CrudError> {
    let domains = read_domains(&state, ListSelector::default(), "").await?;
    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 GET /api/domains/:type — `allow`, `deny`, `exact` or `regex`
/// select lists; anything else is a domain looked up in all of them.
#[utoipa::path(
    get,
    path = "/domains/{type}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "allow, deny, exact, regex, or a domain")
    ),
    responses(
        (status = 200, description = "Matching domains", body = DomainsListResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_by_type(
    State(state): State<PiholeAppState>,
    Path(domain_type): Path<String>,
) -> Result<Json<DomainsListResponse>, CrudError> {
    let (selector, item) = parse_segments(&[&domain_type]);
    let domains = read_domains(&state, selector, &item).await?;
    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 GET /api/domains/:type/:kind — one list, or `{type|kind}/{domain}`.
#[utoipa::path(
    get,
    path = "/domains/{type}/{kind}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "allow, deny, exact or regex"),
        ("kind" = String, Path, description = "exact, regex, or a domain")
    ),
    responses(
        (status = 200, description = "Matching domains", body = DomainsListResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_by_type_kind(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind)): Path<(String, String)>,
) -> Result<Json<DomainsListResponse>, CrudError> {
    let (selector, item) = parse_segments(&[&domain_type, &kind]);
    let domains = read_domains(&state, selector, &item).await?;
    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 GET /api/domains/:type/:kind/:domain — one entry.
#[utoipa::path(
    get,
    path = "/domains/{type}/{kind}/{domain}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type (allow|deny)"),
        ("kind" = String, Path, description = "Match kind (exact|regex)"),
        ("domain" = String, Path, description = "Domain or regex pattern")
    ),
    responses(
        (status = 200, description = "The entry, if it exists", body = DomainsListResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind, domain)): Path<(String, String, String)>,
) -> Result<Json<DomainsListResponse>, CrudError> {
    let (selector, item) = parse_segments(&[&domain_type, &kind, &domain]);
    let domains = read_domains(&state, selector, &item).await?;
    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 POST /api/domains/:type/:kind — add one domain or several.
#[utoipa::path(
    post,
    path = "/domains/{type}/{kind}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type (allow|deny)"),
        ("kind" = String, Path, description = "Match kind (exact|regex)")
    ),
    request_body = CreateDomainRequest,
    responses(
        (status = 201, description = "The last item as stored, and what was processed", body = DomainsWriteResponse),
        (status = 400, description = "Unknown list, bad item, or every item failed")
    ),
    security(("session_id" = []))
)]
pub async fn create_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind)): Path<(String, String)>,
    PiholeJson(body): PiholeJson<CreateDomainRequest>,
) -> Result<Response, CrudError> {
    let list = precise_list(&domain_type, &kind)?;
    let items = require_items(
        body.domain,
        "Invalid request: No valid \"domain\" in payload (must be either string or array)",
    )?
    .into_iter()
    .map(|item| prepare_item(item, list.1))
    .collect::<Result<Vec<_>, _>>()?;
    let group_id = first_group(body.groups.as_deref()).unwrap_or(DEFAULT_GROUP_ID);
    let comment = request_comment(body.comment);
    let enabled = body.enabled.unwrap_or(true);

    let mut present: HashSet<String> = stored_entries(&state, ListSelector::of(list), "")
        .await?
        .iter()
        .map(|e| e.item().to_string())
        .collect();
    let mut processed = Processed::default();
    for item in &items {
        let result = if present.contains(item) {
            Err(DomainError::AlreadyExists(item.clone()))
        } else {
            create_entry(&state, item, list, group_id, comment.clone(), enabled).await
        };
        if result.is_ok() {
            present.insert(item.clone());
        }
        record(&mut processed, item, result)?;
    }

    let status = write_status(&processed, StatusCode::CREATED)?;
    let last = items.last().map(String::as_str).unwrap_or_default();
    let domains = read_domains(&state, ListSelector::of(list), last).await?;
    Ok(write_reply(status, domains, processed))
}

/// Pi-hole v6 PUT /api/domains/:type/:kind/:domain — replace or create the
/// entry; a body `type`/`kind` names the list it moves from.
#[utoipa::path(
    put,
    path = "/domains/{type}/{kind}/{domain}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type"),
        ("kind" = String, Path, description = "Match kind"),
        ("domain" = String, Path, description = "Domain or regex pattern")
    ),
    request_body = UpdateDomainRequest,
    responses(
        (status = 200, description = "The entry as stored, and what was processed", body = DomainsWriteResponse),
        (status = 400, description = "Unknown list, bad item, or the write failed")
    ),
    security(("session_id" = []))
)]
pub async fn update_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind, domain)): Path<(String, String, String)>,
    PiholeJson(body): PiholeJson<UpdateDomainRequest>,
) -> Result<Response, CrudError> {
    let list = precise_list(&domain_type, &kind)?;
    let item = prepare_item(domain, list.1)?;

    let mut processed = Processed::default();
    let result = replace_entry(&state, &item, list, &body).await;
    record(&mut processed, &item, result)?;

    let status = write_status(&processed, StatusCode::OK)?;
    let domains = read_domains(&state, ListSelector::of(list), &item).await?;
    Ok(write_reply(status, domains, processed))
}

/// Pi-hole v6 DELETE /api/domains/:type/:kind/:domain — delete domain.
#[utoipa::path(
    delete,
    path = "/domains/{type}/{kind}/{domain}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type"),
        ("kind" = String, Path, description = "Match kind"),
        ("domain" = String, Path, description = "Domain or regex pattern")
    ),
    responses(
        (status = 204, description = "Domain deleted"),
        (status = 404, description = "Domain not found")
    ),
    security(("session_id" = []))
)]
pub async fn delete_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind, domain)): Path<(String, String, String)>,
) -> Result<Response, CrudError> {
    let list = precise_list(&domain_type, &kind)?;
    let deleted = delete_entries(&state, &[(domain, list)])
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}

/// Pi-hole v6 POST /api/domains:batchDelete — delete `[{item, type, kind}]`.
#[utoipa::path(
    post,
    path = "/domains:batchDelete",
    tag = "pihole:domains",
    request_body = Vec<BatchDeleteItem>,
    responses(
        (status = 204, description = "Items deleted"),
        (status = 400, description = "An item lacks a valid type and kind"),
        (status = 404, description = "Nothing matched")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<Vec<BatchDeleteItem>>,
) -> Result<Response, CrudError> {
    let targets = body
        .into_iter()
        .map(|entry| {
            let (Some(domain_type), Some(kind)) = (entry.item_type, entry.kind) else {
                return Err(CrudError::bad_request(
                    "Invalid request: Batch delete requires an array of objects with \"type\" and \"kind\" as string",
                    None,
                ));
            };
            let list = list_from_body(&domain_type, &kind).ok_or_else(|| {
                CrudError::bad_request(
                    "Invalid request: Batch delete requires an valid combination of \"type\" and \"kind\" for each object",
                    None,
                )
            })?;
            Ok((entry.item, list))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let deleted = delete_entries(&state, &targets)
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(segments: &[&str]) -> (Option<DomainAction>, bool, Option<bool>, String) {
        let (selector, item) = parse_segments(segments);
        (
            selector.action,
            selector.kind.is_some(),
            selector.kind.map(|k| k == DomainKind::Regex),
            item,
        )
    }

    #[test]
    fn segments_resolve_like_ftl_uri_prefixes() {
        assert_eq!(parsed(&[]), (None, false, None, String::new()));
        assert_eq!(
            parsed(&["deny", "exact", "a.com"]),
            (Some(DomainAction::Deny), true, Some(false), "a.com".into())
        );
        assert_eq!(
            parsed(&["allow", "a.com"]),
            (Some(DomainAction::Allow), false, None, "a.com".into())
        );
        assert_eq!(
            parsed(&["regex", "a.com"]),
            (None, true, Some(true), "a.com".into())
        );
        assert_eq!(parsed(&["a.com"]), (None, false, None, "a.com".into()));
        assert_eq!(parsed(&["Allow"]), (None, false, None, "Allow".into()));
    }

    #[test]
    fn writes_need_both_a_type_and_a_kind() {
        assert!(precise_list("deny", "regex").is_ok());
        assert!(precise_list("deny", "a.com").is_err());
        assert!(precise_list("exact", "deny").is_err());
    }
}
