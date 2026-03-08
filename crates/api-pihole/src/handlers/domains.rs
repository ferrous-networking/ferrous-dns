use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use ferrous_dns_domain::DomainAction;

use crate::{
    dto::domains::{
        BatchDeleteRequest, CreateDomainRequest, DomainsListResponse, PiholeDomainEntry,
    },
    errors::PiholeApiError,
    state::PiholeAppState,
};

fn map_type(t: &str) -> Option<DomainAction> {
    match t {
        "allow" => Some(DomainAction::Allow),
        "deny" => Some(DomainAction::Deny),
        _ => None,
    }
}

fn domain_to_entry(
    d: &ferrous_dns_domain::ManagedDomain,
) -> Result<PiholeDomainEntry, PiholeApiError> {
    Ok(PiholeDomainEntry {
        id: d.id.ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                "managed domain missing id".into(),
            ))
        })?,
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

fn regex_to_entry(
    r: &ferrous_dns_domain::RegexFilter,
) -> Result<PiholeDomainEntry, PiholeApiError> {
    Ok(PiholeDomainEntry {
        id: r.id.ok_or_else(|| {
            PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                "regex filter missing id".into(),
            ))
        })?,
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
pub async fn list_by_type(
    State(state): State<PiholeAppState>,
    Path(domain_type): Path<String>,
) -> Result<Json<DomainsListResponse>, PiholeApiError> {
    let action = map_type(&domain_type).ok_or_else(|| {
        PiholeApiError(ferrous_dns_domain::DomainError::InvalidDomainName(format!(
            "Unknown domain type: {domain_type}"
        )))
    })?;

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
pub async fn list_by_type_kind(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind)): Path<(String, String)>,
) -> Result<Json<DomainsListResponse>, PiholeApiError> {
    let action = map_type(&domain_type).ok_or_else(|| {
        PiholeApiError(ferrous_dns_domain::DomainError::InvalidDomainName(format!(
            "Unknown domain type: {domain_type}"
        )))
    })?;

    let domains: Vec<PiholeDomainEntry> = match kind.as_str() {
        "exact" => {
            let managed = state.blocking.get_managed_domains.get_all().await?;
            managed
                .iter()
                .filter(|d| d.action == action)
                .map(domain_to_entry)
                .collect::<Result<Vec<_>, _>>()?
        }
        "regex" => {
            let regexes = state.blocking.get_regex_filters.get_all().await?;
            regexes
                .iter()
                .filter(|r| r.action == action)
                .map(regex_to_entry)
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => Vec::new(),
    };

    Ok(Json(DomainsListResponse { domains }))
}

/// Pi-hole v6 POST /api/domains/:type/:kind — create domain.
pub async fn create_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind)): Path<(String, String)>,
    Json(body): Json<CreateDomainRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let action = map_type(&domain_type).ok_or_else(|| {
        PiholeApiError(ferrous_dns_domain::DomainError::InvalidDomainName(format!(
            "Unknown domain type: {domain_type}"
        )))
    })?;
    let group_id = body
        .groups
        .as_ref()
        .and_then(|g| g.first().copied())
        .unwrap_or(1);
    let enabled = body.enabled.unwrap_or(true);

    match kind.as_str() {
        "exact" => {
            let name = body.domain.clone();
            let result = state
                .blocking
                .create_managed_domain
                .execute(name, body.domain, action, group_id, body.comment, enabled)
                .await?;
            let entry = domain_to_entry(&result)?;
            Ok((StatusCode::CREATED, Json(entry)))
        }
        "regex" => {
            let name = body.domain.clone();
            let result = state
                .blocking
                .create_regex_filter
                .execute(name, body.domain, action, group_id, body.comment, enabled)
                .await?;
            let entry = regex_to_entry(&result)?;
            Ok((StatusCode::CREATED, Json(entry)))
        }
        _ => Err(PiholeApiError(
            ferrous_dns_domain::DomainError::InvalidDomainName(format!("Unknown kind: {kind}")),
        )),
    }
}

/// Pi-hole v6 PUT /api/domains/:type/:kind/:domain — update domain.
pub async fn update_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind, domain_name)): Path<(String, String, String)>,
    Json(body): Json<CreateDomainRequest>,
) -> Result<Json<PiholeDomainEntry>, PiholeApiError> {
    let action = map_type(&domain_type);
    let group_id = body.groups.as_ref().and_then(|g| g.first().copied());

    match kind.as_str() {
        "exact" => {
            let all = state.blocking.get_managed_domains.get_all().await?;
            let existing = all
                .iter()
                .find(|d| d.domain.as_ref() == domain_name)
                .ok_or_else(|| {
                    PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                        "Domain {domain_name} not found"
                    )))
                })?;
            let id = existing.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            let result = state
                .blocking
                .update_managed_domain
                .execute(
                    id,
                    None,
                    Some(body.domain),
                    action,
                    group_id,
                    body.comment,
                    body.enabled,
                )
                .await?;
            Ok(Json(domain_to_entry(&result)?))
        }
        "regex" => {
            let all = state.blocking.get_regex_filters.get_all().await?;
            let existing = all
                .iter()
                .find(|r| r.pattern.as_ref() == domain_name)
                .ok_or_else(|| {
                    PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                        "Regex {domain_name} not found"
                    )))
                })?;
            let id = existing.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            let result = state
                .blocking
                .update_regex_filter
                .execute(
                    id,
                    None,
                    Some(body.domain),
                    action,
                    group_id,
                    body.comment,
                    body.enabled,
                )
                .await?;
            Ok(Json(regex_to_entry(&result)?))
        }
        _ => Err(PiholeApiError(
            ferrous_dns_domain::DomainError::InvalidDomainName(format!("Unknown kind: {kind}")),
        )),
    }
}

/// Pi-hole v6 DELETE /api/domains/:type/:kind/:domain — delete domain.
pub async fn delete_domain(
    State(state): State<PiholeAppState>,
    Path((domain_type, kind, domain_name)): Path<(String, String, String)>,
) -> Result<StatusCode, PiholeApiError> {
    let action = map_type(&domain_type).ok_or_else(|| {
        PiholeApiError(ferrous_dns_domain::DomainError::InvalidDomainName(format!(
            "Unknown domain type: {domain_type}"
        )))
    })?;

    match kind.as_str() {
        "exact" => {
            let all = state.blocking.get_managed_domains.get_all().await?;
            let existing = all
                .iter()
                .find(|d| d.domain.as_ref() == domain_name && d.action == action)
                .ok_or_else(|| {
                    PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                        "Domain {domain_name} not found in {domain_type} list"
                    )))
                })?;
            let id = existing.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            state.blocking.delete_managed_domain.execute(id).await?;
        }
        "regex" => {
            let all = state.blocking.get_regex_filters.get_all().await?;
            let existing = all
                .iter()
                .find(|r| r.pattern.as_ref() == domain_name && r.action == action)
                .ok_or_else(|| {
                    PiholeApiError(ferrous_dns_domain::DomainError::NotFound(format!(
                        "Regex {domain_name} not found in {domain_type} list"
                    )))
                })?;
            let id = existing.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            state.blocking.delete_regex_filter.execute(id).await?;
        }
        _ => {
            return Err(PiholeApiError(
                ferrous_dns_domain::DomainError::InvalidDomainName(format!("Unknown kind: {kind}")),
            ));
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
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    Json(body): Json<BatchDeleteRequest>,
) -> Result<StatusCode, PiholeApiError> {
    let all_managed = state.blocking.get_managed_domains.get_all().await?;
    let all_regex = state.blocking.get_regex_filters.get_all().await?;

    for item in &body.items {
        if let Some(d) = all_managed
            .iter()
            .find(|d| d.domain.as_ref() == item.as_str())
        {
            let id = d.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            state.blocking.delete_managed_domain.execute(id).await?;
        } else if let Some(r) = all_regex
            .iter()
            .find(|r| r.pattern.as_ref() == item.as_str())
        {
            let id = r.id.ok_or_else(|| {
                PiholeApiError(ferrous_dns_domain::DomainError::DatabaseError(
                    "record missing id".into(),
                ))
            })?;
            state.blocking.delete_regex_filter.execute(id).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}
