use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use ferrous_dns_domain::DomainError;
use serde::Deserialize;
use tracing::debug;

use crate::{
    dto::{BlockServiceRequest, BlockedServiceResponse, ServiceDefinitionResponse},
    errors::ApiError,
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
    let services = state.services.get_service_catalog.get_all();
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
) -> Result<Json<ServiceDefinitionResponse>, ApiError> {
    let def = state
        .services
        .get_service_catalog
        .get_by_id(&id)
        .ok_or_else(|| {
            ApiError(DomainError::ServiceNotFoundInCatalog(format!(
                "Service '{}' not found in catalog",
                id
            )))
        })?;
    Ok(Json(ServiceDefinitionResponse::from_definition(&def)))
}

#[derive(Deserialize)]
struct BlockedServicesQuery {
    group_id: Option<i64>,
}

async fn get_blocked_services(
    State(state): State<AppState>,
    Query(params): Query<BlockedServicesQuery>,
) -> Result<Json<Vec<BlockedServiceResponse>>, ApiError> {
    let services = match params.group_id {
        Some(gid) => {
            state
                .services
                .get_blocked_services
                .get_for_group(gid)
                .await?
        }
        None => state.services.get_blocked_services.get_all().await?,
    };
    debug!(count = services.len(), "Blocked services retrieved");
    Ok(Json(
        services
            .into_iter()
            .map(BlockedServiceResponse::from_entity)
            .collect(),
    ))
}

async fn block_service(
    State(state): State<AppState>,
    Json(req): Json<BlockServiceRequest>,
) -> Result<(StatusCode, Json<BlockedServiceResponse>), ApiError> {
    let blocked = state
        .services
        .block_service
        .execute(&req.service_id, req.group_id)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(BlockedServiceResponse::from_entity(blocked)),
    ))
}

async fn unblock_service(
    State(state): State<AppState>,
    Path((service_id, group_id)): Path<(String, i64)>,
) -> Result<StatusCode, ApiError> {
    state
        .services
        .unblock_service
        .execute(&service_id, group_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
