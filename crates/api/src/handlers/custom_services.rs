use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{CreateCustomServiceRequest, CustomServiceResponse, UpdateCustomServiceRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_custom_services, create_custom_service))
        .routes(routes!(
            get_custom_service,
            update_custom_service,
            delete_custom_service
        ))
}

#[utoipa::path(
    get,
    path = "/custom-services",
    tag = "custom_services",
    responses(
        (status = 200, description = "All custom services", body = [CustomServiceResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_custom_services(
    State(state): State<AppState>,
) -> Result<Json<Vec<CustomServiceResponse>>, ApiError> {
    let services = state.services.get_custom_services.get_all().await?;
    debug!(count = services.len(), "Custom services listed");
    Ok(Json(
        services
            .into_iter()
            .map(CustomServiceResponse::from_entity)
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/custom-services/{service_id}",
    tag = "custom_services",
    params(("service_id" = String, Path, description = "Custom service ID")),
    responses(
        (status = 200, description = "Custom service detail", body = CustomServiceResponse),
        (status = 404, description = "Custom service not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_custom_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
) -> Result<Json<CustomServiceResponse>, ApiError> {
    let cs = state
        .services
        .get_custom_services
        .get_by_service_id(&service_id)
        .await?
        .ok_or_else(|| {
            ApiError(DomainError::CustomServiceNotFound(format!(
                "Custom service '{}' not found",
                service_id
            )))
        })?;
    Ok(Json(CustomServiceResponse::from_entity(cs)))
}

#[utoipa::path(
    post,
    path = "/custom-services",
    tag = "custom_services",
    request_body = CreateCustomServiceRequest,
    responses(
        (status = 201, description = "Custom service created", body = CustomServiceResponse),
        (status = 409, description = "Custom service already exists"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_custom_service(
    State(state): State<AppState>,
    Json(req): Json<CreateCustomServiceRequest>,
) -> Result<(StatusCode, Json<CustomServiceResponse>), ApiError> {
    let category = req.category_name.as_deref().unwrap_or("Custom");

    let cs = state
        .services
        .create_custom_service
        .execute(&req.name, category, req.domains)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CustomServiceResponse::from_entity(cs)),
    ))
}

#[utoipa::path(
    patch,
    path = "/custom-services/{service_id}",
    tag = "custom_services",
    params(("service_id" = String, Path, description = "Custom service ID")),
    request_body = UpdateCustomServiceRequest,
    responses(
        (status = 200, description = "Custom service updated", body = CustomServiceResponse),
        (status = 404, description = "Custom service not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_custom_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Json(req): Json<UpdateCustomServiceRequest>,
) -> Result<Json<CustomServiceResponse>, ApiError> {
    let cs = state
        .services
        .update_custom_service
        .execute(&service_id, req.name, req.category_name, req.domains)
        .await?;
    Ok(Json(CustomServiceResponse::from_entity(cs)))
}

#[utoipa::path(
    delete,
    path = "/custom-services/{service_id}",
    tag = "custom_services",
    params(("service_id" = String, Path, description = "Custom service ID")),
    responses(
        (status = 204, description = "Custom service deleted"),
        (status = 404, description = "Custom service not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_custom_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .services
        .delete_custom_service
        .execute(&service_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
