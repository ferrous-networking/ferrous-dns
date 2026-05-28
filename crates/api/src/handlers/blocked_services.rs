use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use serde::Deserialize;
use tracing::debug;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{BlockServiceRequest, BlockedServiceResponse, ServiceDefinitionResponse},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_catalog))
        .routes(routes!(get_catalog_entry))
        .routes(routes!(get_blocked_services, block_service))
        .routes(routes!(unblock_service))
}

#[utoipa::path(
    get,
    path = "/services/catalog",
    tag = "services",
    responses(
        (status = 200, description = "Service catalog", body = [ServiceDefinitionResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_catalog(State(state): State<AppState>) -> Json<Vec<ServiceDefinitionResponse>> {
    let services = state.services.get_service_catalog.get_all();
    Json(
        services
            .iter()
            .map(ServiceDefinitionResponse::from_definition)
            .collect(),
    )
}

#[utoipa::path(
    get,
    path = "/services/catalog/{id}",
    tag = "services",
    params(("id" = String, Path, description = "Service ID")),
    responses(
        (status = 200, description = "Service definition", body = ServiceDefinitionResponse),
        (status = 404, description = "Service not found in catalog"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[derive(Deserialize, IntoParams)]
struct BlockedServicesQuery {
    group_id: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/services",
    tag = "services",
    params(("group_id" = Option<i64>, Query, description = "Optional group filter")),
    responses(
        (status = 200, description = "Blocked services", body = [BlockedServiceResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/services",
    tag = "services",
    request_body = BlockServiceRequest,
    responses(
        (status = 201, description = "Service blocked for group", body = BlockedServiceResponse),
        (status = 409, description = "Service already blocked for this group"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    delete,
    path = "/services/{service_id}/groups/{group_id}",
    tag = "services",
    params(
        ("service_id" = String, Path, description = "Service ID"),
        ("group_id" = i64, Path, description = "Group ID"),
    ),
    responses(
        (status = 204, description = "Service unblocked"),
        (status = 404, description = "Blocked service not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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
