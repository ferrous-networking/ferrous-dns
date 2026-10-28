use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_application::ports::ManagedDomainUpdate;
use ferrous_dns_domain::DomainError;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{
        managed_domain::parse_action, CreateManagedDomainRequest, ManagedDomainQuery,
        ManagedDomainResponse, PaginatedManagedDomains, UpdateManagedDomainRequest,
    },
    errors::ApiError,
    state::AppState,
};

/// Upper bound on how many managed domains a single listing request may return.
const MAX_MANAGED_DOMAINS_LIMIT: u32 = 1_000;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_managed_domains, create_managed_domain))
        .routes(routes!(
            get_managed_domain_by_id,
            update_managed_domain,
            delete_managed_domain
        ))
}

#[utoipa::path(
    get,
    path = "/managed-domains",
    tag = "blocking",
    params(ManagedDomainQuery),
    responses(
        (status = 200, description = "Paginated managed domains", body = PaginatedManagedDomains),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_managed_domains(
    State(state): State<AppState>,
    Query(params): Query<ManagedDomainQuery>,
) -> Result<Json<PaginatedManagedDomains>, ApiError> {
    let limit = params.limit.clamp(1, MAX_MANAGED_DOMAINS_LIMIT);
    let (domains, total) = state
        .blocking
        .get_managed_domains
        .get_all_paged(limit, params.offset)
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
        limit,
        offset: params.offset,
    }))
}

#[utoipa::path(
    get,
    path = "/managed-domains/{id}",
    tag = "blocking",
    params(("id" = i64, Path, description = "Managed domain ID")),
    responses(
        (status = 200, description = "Managed domain detail", body = ManagedDomainResponse),
        (status = 404, description = "Managed domain not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_managed_domain_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ManagedDomainResponse>, ApiError> {
    let domain = state
        .blocking
        .get_managed_domains
        .get_by_id(id)
        .await?
        .ok_or(ApiError(DomainError::ManagedDomainNotFound(id)))?;
    Ok(Json(ManagedDomainResponse::from_domain(domain)))
}

#[utoipa::path(
    post,
    path = "/managed-domains",
    tag = "blocking",
    request_body = CreateManagedDomainRequest,
    responses(
        (status = 201, description = "Managed domain created", body = ManagedDomainResponse),
        (status = 400, description = "Invalid input"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_managed_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateManagedDomainRequest>,
) -> Result<(StatusCode, Json<ManagedDomainResponse>), ApiError> {
    let action = parse_action(&req.action)?;

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

#[utoipa::path(
    put,
    path = "/managed-domains/{id}",
    tag = "blocking",
    params(("id" = i64, Path, description = "Managed domain ID")),
    request_body = UpdateManagedDomainRequest,
    responses(
        (status = 200, description = "Managed domain updated", body = ManagedDomainResponse),
        (status = 404, description = "Managed domain not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_managed_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateManagedDomainRequest>,
) -> Result<Json<ManagedDomainResponse>, ApiError> {
    let action = req.action.as_deref().map(parse_action).transpose()?;

    let domain = state
        .blocking
        .update_managed_domain
        .execute(
            id,
            ManagedDomainUpdate {
                name: req.name,
                domain: req.domain,
                action,
                group_id: req.group_id,
                comment: req.comment,
                enabled: req.enabled,
            },
        )
        .await?;

    Ok(Json(ManagedDomainResponse::from_domain(domain)))
}

#[utoipa::path(
    delete,
    path = "/managed-domains/{id}",
    tag = "blocking",
    params(("id" = i64, Path, description = "Managed domain ID")),
    responses(
        (status = 204, description = "Managed domain deleted"),
        (status = 404, description = "Managed domain not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_managed_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.blocking.delete_managed_domain.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
