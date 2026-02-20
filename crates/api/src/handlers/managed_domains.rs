use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use tracing::{debug, error};

use crate::{
    dto::{CreateManagedDomainRequest, ManagedDomainResponse, UpdateManagedDomainRequest},
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
) -> Json<Vec<ManagedDomainResponse>> {
    match state.get_managed_domains.get_all().await {
        Ok(domains) => {
            debug!(
                count = domains.len(),
                "Managed domains retrieved successfully"
            );
            Json(
                domains
                    .into_iter()
                    .map(ManagedDomainResponse::from_domain)
                    .collect(),
            )
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve managed domains");
            Json(vec![])
        }
    }
}

async fn get_managed_domain_by_id(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ManagedDomainResponse>, (StatusCode, String)> {
    match state.get_managed_domains.get_by_id(id).await {
        Ok(Some(domain)) => Ok(Json(ManagedDomainResponse::from_domain(domain))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("Managed domain {} not found", id),
        )),
        Err(e) => {
            error!(error = %e, "Failed to retrieve managed domain");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn create_managed_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateManagedDomainRequest>,
) -> Result<(StatusCode, Json<ManagedDomainResponse>), (StatusCode, String)> {
    let action = req.action.parse::<DomainAction>().ok().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid action '{}': must be 'allow' or 'deny'", req.action),
        )
    })?;

    let group_id = req.group_id.unwrap_or(1);
    let enabled = req.enabled.unwrap_or(true);

    match state
        .create_managed_domain
        .execute(req.name, req.domain, action, group_id, req.comment, enabled)
        .await
    {
        Ok(domain) => Ok((
            StatusCode::CREATED,
            Json(ManagedDomainResponse::from_domain(domain)),
        )),
        Err(DomainError::InvalidManagedDomain(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to create managed domain");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

async fn update_managed_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateManagedDomainRequest>,
) -> Result<Json<ManagedDomainResponse>, (StatusCode, String)> {
    let action = match req.action {
        Some(ref s) => Some(s.parse::<DomainAction>().ok().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid action '{}': must be 'allow' or 'deny'", s),
            )
        })?),
        None => None,
    };

    match state
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
        .await
    {
        Ok(domain) => Ok(Json(ManagedDomainResponse::from_domain(domain))),
        Err(e @ DomainError::ManagedDomainNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, e.to_string()))
        }
        Err(DomainError::InvalidManagedDomain(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to update managed domain");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_managed_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_managed_domain.execute(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e @ DomainError::ManagedDomainNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, e.to_string()))
        }
        Err(e) => {
            error!(error = %e, "Failed to delete managed domain");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
