use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, patch, post},
    Router,
};
use ferrous_dns_domain::DomainError;
use tracing::debug;

use crate::{
    dto::{CreateCustomServiceRequest, CustomServiceResponse, UpdateCustomServiceRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/custom-services", get(list_custom_services))
        .route("/custom-services", post(create_custom_service))
        .route("/custom-services/{service_id}", get(get_custom_service))
        .route(
            "/custom-services/{service_id}",
            patch(update_custom_service),
        )
        .route(
            "/custom-services/{service_id}",
            delete(delete_custom_service),
        )
}

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
