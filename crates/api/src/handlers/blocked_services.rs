use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use ferrous_dns_domain::DomainError;
use serde::Deserialize;
use tracing::{debug, error};

use crate::{
    dto::{BlockServiceRequest, BlockedServiceResponse, ServiceDefinitionResponse},
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/services/catalog", get(get_catalog))
        .route("/services/catalog/{id}", get(get_catalog_entry))
        .route("/services", get(get_blocked_services))
        .route("/services", post(block_service))
        .route(
            "/services/{service_id}/groups/{group_id}",
            delete(unblock_service),
        )
}

async fn get_catalog(State(state): State<AppState>) -> Json<Vec<ServiceDefinitionResponse>> {
    let services = state.get_service_catalog.get_all();
    Json(
        services
            .iter()
            .map(ServiceDefinitionResponse::from_definition)
            .collect(),
    )
}

async fn get_catalog_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ServiceDefinitionResponse>, (StatusCode, String)> {
    state
        .get_service_catalog
        .get_by_id(&id)
        .map(|d| Json(ServiceDefinitionResponse::from_definition(&d)))
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Service '{}' not found in catalog", id),
            )
        })
}

#[derive(Deserialize)]
struct BlockedServicesQuery {
    group_id: Option<i64>,
}

async fn get_blocked_services(
    State(state): State<AppState>,
    Query(params): Query<BlockedServicesQuery>,
) -> Json<Vec<BlockedServiceResponse>> {
    let result = match params.group_id {
        Some(gid) => state.get_blocked_services.get_for_group(gid).await,
        None => state.get_blocked_services.get_all().await,
    };

    match result {
        Ok(services) => {
            debug!(count = services.len(), "Blocked services retrieved");
            Json(
                services
                    .into_iter()
                    .map(BlockedServiceResponse::from_entity)
                    .collect(),
            )
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve blocked services");
            Json(vec![])
        }
    }
}

async fn block_service(
    State(state): State<AppState>,
    Json(req): Json<BlockServiceRequest>,
) -> Result<(StatusCode, Json<BlockedServiceResponse>), (StatusCode, String)> {
    match state
        .block_service
        .execute(&req.service_id, req.group_id)
        .await
    {
        Ok(blocked) => Ok((
            StatusCode::CREATED,
            Json(BlockedServiceResponse::from_entity(blocked)),
        )),
        Err(DomainError::ServiceNotFoundInCatalog(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(DomainError::BlockedServiceAlreadyExists(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to block service");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn unblock_service(
    State(state): State<AppState>,
    Path((service_id, group_id)): Path<(String, i64)>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.unblock_service.execute(&service_id, group_id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e @ DomainError::NotFound(_)) => Err((StatusCode::NOT_FOUND, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to unblock service");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
