use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use tracing::debug;

use crate::{
    dto::{
        CreateManagedDomainRequest, ManagedDomainQuery, ManagedDomainResponse,
        PaginatedManagedDomains, UpdateManagedDomainRequest,
    },
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/managed-domains", get(get_all_managed_domains))
        .route("/managed-domains", post(create_managed_domain))
        .route("/managed-domains/{id}", get(get_managed_domain_by_id))
        .route("/managed-domains/{id}", put(update_managed_domain))
        .route("/managed-domains/{id}", delete(delete_managed_domain))
}

async fn get_all_managed_domains(
    State(state): State<AppState>,
    Query(params): Query<ManagedDomainQuery>,
) -> Result<Json<PaginatedManagedDomains>, ApiError> {
    let (domains, total) = state
        .blocking
        .get_managed_domains
        .get_all_paged(params.limit, params.offset)
        .await?;
    debug!(
        count = domains.len(),
        total, "Managed domains retrieved successfully"
    );
    Ok(Json(PaginatedManagedDomains {
        data: domains
            .into_iter()
            .map(ManagedDomainResponse::from_domain)
            .collect(),
        total,
        limit: params.limit,
        offset: params.offset,
    }))
}

async fn get_managed_domain_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ManagedDomainResponse>, ApiError> {
    let domain = state
        .blocking
        .get_managed_domains
        .get_by_id(id)
        .await?
        .ok_or_else(|| {
            ApiError(DomainError::NotFound(format!(
                "Managed domain {} not found",
                id
            )))
        })?;
    Ok(Json(ManagedDomainResponse::from_domain(domain)))
}

async fn create_managed_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateManagedDomainRequest>,
) -> Result<(StatusCode, Json<ManagedDomainResponse>), ApiError> {
    let action = req.action.parse::<DomainAction>().ok().ok_or_else(|| {
        ApiError(DomainError::InvalidDomainName(format!(
            "Invalid action '{}': must be 'allow' or 'deny'",
            req.action
        )))
    })?;

    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    let domain = state
        .blocking
        .create_managed_domain
        .execute(req.name, req.domain, action, group_id, req.comment, enabled)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ManagedDomainResponse::from_domain(domain)),
    ))
}

async fn update_managed_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateManagedDomainRequest>,
) -> Result<Json<ManagedDomainResponse>, ApiError> {
    let action = match req.action {
        Some(ref s) => Some(s.parse::<DomainAction>().ok().ok_or_else(|| {
            ApiError(DomainError::InvalidDomainName(format!(
                "Invalid action '{}': must be 'allow' or 'deny'",
                s
            )))
        })?),
        None => None,
    };

    let domain = state
        .blocking
        .update_managed_domain
        .execute(
            id,
            req.name,
            req.domain,
            action,
            req.group_id,
            req.comment,
            req.enabled,
        )
        .await?;

    Ok(Json(ManagedDomainResponse::from_domain(domain)))
}

async fn delete_managed_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_managed_domain.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
