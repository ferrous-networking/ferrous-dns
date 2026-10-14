use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use ferrous_dns_application::ports::{ManagedDomainUpdate, RegexFilterUpdate};
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain, RegexFilter};

use crate::{
    dto::domains::{
        BatchDeleteRequest, CreateDomainRequest, DomainsListResponse, PiholeDomainEntry,
    },
    errors::PiholeApiError,
    extract::PiholeJson,
    handlers::require_id,
    state::PiholeAppState,
};

/// The `{kind}` path segment: exact entries are managed domains, regex
/// entries are regex filters.
#[derive(Clone, Copy)]
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

fn parse_kind(kind: &str) -> Result<DomainKind, DomainError> {
    DomainKind::from_path(kind)
        .ok_or_else(|| DomainError::InvalidDomainName(format!("Unknown kind: {kind}")))
}

fn parse_action(domain_type: &str) -> Result<DomainAction, DomainError> {
    domain_type
        .parse()
        .map_err(|_| DomainError::InvalidDomainName(format!("Unknown domain type: {domain_type}")))
}

fn domain_to_entry(d: &ManagedDomain) -> Result<PiholeDomainEntry, DomainError> {
    Ok(PiholeDomainEntry {
        id: require_id(d.id, "managed domain")?,
        domain: d.domain.to_string(),
        r#type: d.action.to_str(),
        kind: "exact",
        enabled: d.enabled,
        comment: d.comment.as_ref().map(|c| c.to_string()),
        groups: vec![d.group_id],
        date_added: d.created_at.clone(),
        date_modified: d.updated_at.clone(),
    })
}

fn regex_to_entry(r: &RegexFilter) -> Result<PiholeDomainEntry, DomainError> {
    Ok(PiholeDomainEntry {
        id: require_id(r.id, "regex filter")?,
        domain: r.pattern.to_string(),
        r#type: r.action.to_str(),
        kind: "regex",
        enabled: r.enabled,
        comment: r.comment.as_ref().map(|c| c.to_string()),
        groups: vec![r.group_id],
        date_added: r.created_at.clone(),
        date_modified: r.updated_at.clone(),
    })
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
) -> Result<Json<DomainsListResponse>, PiholeApiError> {
    let (managed, regexes) = tokio::join!(
        state.blocking.get_managed_domains.get_all(),
        state.blocking.get_regex_filters.get_all(),
    );

    let mut domains: Vec<PiholeDomainEntry> = Vec::new();
    for d in managed? {
        domains.push(domain_to_entry(&d)?);
    }
    for r in regexes? {
        domains.push(regex_to_entry(&r)?);
    }

    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 GET /api/domains/:type — list by allow/deny.
#[utoipa::path(
    get,
    path = "/domains/{type}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type (allow|deny)")
    ),
    responses(
        (status = 200, description = "Domains filtered by action", body = DomainsListResponse),
        (status = 422, description = "Unknown type")
    ),
    security(("session_id" = []))
)]
pub async fn list_by_type(
    State(state): State<PiholeAppState>,
    Path(domain_type): Path<String>,
) -> Result<Json<DomainsListResponse>, PiholeApiError> {
    let action = parse_action(&domain_type)?;

    let (managed, regexes) = tokio::join!(
        state.blocking.get_managed_domains.get_all(),
        state.blocking.get_regex_filters.get_all(),
    );

    let mut domains: Vec<PiholeDomainEntry> = Vec::new();
    for d in managed?.iter().filter(|d| d.action == action) {
        domains.push(domain_to_entry(d)?);
    }
    for r in regexes?.iter().filter(|r| r.action == action) {
        domains.push(regex_to_entry(r)?);
    }

    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 GET /api/domains/:type/:kind — list by type+kind.
#[utoipa::path(
    get,
    path = "/domains/{type}/{kind}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type (allow|deny)"),
        ("kind" = String, Path, description = "Match kind (exact|regex)")
    ),
    responses(
        (status = 200, description = "Domains filtered by type and kind", body = DomainsListResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_by_type_kind(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind)): Path<(String, String)>,
) -> Result<Json<DomainsListResponse>, PiholeApiError> {
    let action = parse_action(&domain_type)?;

    let domains: Vec<PiholeDomainEntry> = match DomainKind::from_path(&kind) {
        Some(DomainKind::Exact) => {
            let managed = state.blocking.get_managed_domains.get_all().await?;
            managed
                .iter()
                .filter(|d| d.action == action)
                .map(domain_to_entry)
                .collect::<Result<Vec<_>, _>>()?
        }
        Some(DomainKind::Regex) => {
            let regexes = state.blocking.get_regex_filters.get_all().await?;
            regexes
                .iter()
                .filter(|r| r.action == action)
                .map(regex_to_entry)
                .collect::<Result<Vec<_>, _>>()?
        }
        None => Vec::new(),
    };

    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 POST /api/domains/:type/:kind — create domain.
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
        (status = 201, description = "Domain created", body = PiholeDomainEntry),
        (status = 422, description = "Invalid type or kind")
    ),
    security(("session_id" = []))
)]
pub async fn create_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind)): Path<(String, String)>,
    PiholeJson(body): PiholeJson<CreateDomainRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let action = parse_action(&domain_type)?;
    let group_id = body
        .groups
        .as_ref()
        .and_then(|g| g.first().copied())
        .unwrap_or(1);
    let enabled = body.enabled.unwrap_or(true);

    match parse_kind(&kind)? {
        DomainKind::Exact => {
            let name = body.domain.clone();
            let result = state
                .blocking
                .create_managed_domain
                .execute(name, body.domain, action, group_id, body.comment, enabled)
                .await?;
            let entry = domain_to_entry(&result)?;
            Ok((StatusCode::CREATED, Json(entry)))
        }
        DomainKind::Regex => {
            let name = body.domain.clone();
            let result = state
                .blocking
                .create_regex_filter
                .execute(name, body.domain, action, group_id, body.comment, enabled)
                .await?;
            let entry = regex_to_entry(&result)?;
            Ok((StatusCode::CREATED, Json(entry)))
        }
    }
}

/// Pi-hole v6 PUT /api/domains/:type/:kind/:domain — update domain.
#[utoipa::path(
    put,
    path = "/domains/{type}/{kind}/{domain}",
    tag = "pihole:domains",
    params(
        ("type" = String, Path, description = "Action type"),
        ("kind" = String, Path, description = "Match kind"),
        ("domain" = String, Path, description = "Domain or regex pattern")
    ),
    request_body = CreateDomainRequest,
    responses(
        (status = 200, description = "Domain updated", body = PiholeDomainEntry),
        (status = 404, description = "Domain not found")
    ),
    security(("session_id" = []))
)]
pub async fn update_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind, domain_name)): Path<(String, String, String)>,
    PiholeJson(body): PiholeJson<CreateDomainRequest>,
) -> Result<Json<PiholeDomainEntry>, PiholeApiError> {
    // An unknown type keeps the entry's current action.
    let action = domain_type.parse::<DomainAction>().ok();
    let group_id = body.groups.as_ref().and_then(|g| g.first().copied());

    match parse_kind(&kind)? {
        DomainKind::Exact => {
            let all = state.blocking.get_managed_domains.get_all().await?;
            let existing = all
                .iter()
                .find(|d| d.domain.as_ref() == domain_name)
                .ok_or_else(|| DomainError::NotFound(format!("Domain {domain_name} not found")))?;
            let id = require_id(existing.id, "managed domain")?;
            let result = state
                .blocking
                .update_managed_domain
                .execute(
                    id,
                    ManagedDomainUpdate {
                        domain: Some(body.domain),
                        action,
                        group_id,
                        comment: body.comment.map(Some),
                        enabled: body.enabled,
                        ..Default::default()
                    },
                )
                .await?;
            Ok(Json(domain_to_entry(&result)?))
        }
        DomainKind::Regex => {
            let all = state.blocking.get_regex_filters.get_all().await?;
            let existing = all
                .iter()
                .find(|r| r.pattern.as_ref() == domain_name)
                .ok_or_else(|| DomainError::NotFound(format!("Regex {domain_name} not found")))?;
            let id = require_id(existing.id, "regex filter")?;
            let result = state
                .blocking
                .update_regex_filter
                .execute(
                    id,
                    RegexFilterUpdate {
                        pattern: Some(body.domain),
                        action,
                        group_id,
                        comment: body.comment.map(Some),
                        enabled: body.enabled,
                        ..Default::default()
                    },
                )
                .await?;
            Ok(Json(regex_to_entry(&result)?))
        }
    }
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
    Path((domain_type, kind, domain_name)): Path<(String, String, String)>,
) -> Result<StatusCode, PiholeApiError> {
    let action = parse_action(&domain_type)?;

    match parse_kind(&kind)? {
        DomainKind::Exact => {
            let all = state.blocking.get_managed_domains.get_all().await?;
            let existing = all
                .iter()
                .find(|d| d.domain.as_ref() == domain_name && d.action == action)
                .ok_or_else(|| {
                    DomainError::NotFound(format!(
                        "Domain {domain_name} not found in {domain_type} list"
                    ))
                })?;
            let id = require_id(existing.id, "managed domain")?;
            state.blocking.delete_managed_domain.execute(id).await?;
        }
        DomainKind::Regex => {
            let all = state.blocking.get_regex_filters.get_all().await?;
            let existing = all
                .iter()
                .find(|r| r.pattern.as_ref() == domain_name && r.action == action)
                .ok_or_else(|| {
                    DomainError::NotFound(format!(
                        "Regex {domain_name} not found in {domain_type} list"
                    ))
                })?;
            let id = require_id(existing.id, "regex filter")?;
            state.blocking.delete_regex_filter.execute(id).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Pi-hole v6 POST /api/domains:batchDelete — batch delete domains.
///
/// NOTE: This endpoint does not filter by action (allow/deny) because the
/// batch delete URL path (`/domains:batchDelete`) has no type context.
/// Items are matched by exact domain/pattern across both managed and regex
/// entries regardless of their action.
#[utoipa::path(
    post,
    path = "/domains:batchDelete",
    tag = "pihole:domains",
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
    let all_managed = state.blocking.get_managed_domains.get_all().await?;
    let all_regex = state.blocking.get_regex_filters.get_all().await?;

    for item in &body.items {
        if let Some(d) = all_managed
            .iter()
            .find(|d| d.domain.as_ref() == item.as_str())
        {
            let id = require_id(d.id, "managed domain")?;
            state.blocking.delete_managed_domain.execute(id).await?;
        } else if let Some(r) = all_regex
            .iter()
            .find(|r| r.pattern.as_ref() == item.as_str())
        {
            let id = require_id(r.id, "regex filter")?;
            state.blocking.delete_regex_filter.execute(id).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}
