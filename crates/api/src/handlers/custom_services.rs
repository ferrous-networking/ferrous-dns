use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, patch, post},
    Router,
};
use ferrous_dns_domain::DomainError;
use tracing::{debug, error};

use crate::{
    dto::{CreateCustomServiceRequest, CustomServiceResponse, UpdateCustomServiceRequest},
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
) -> Result<Json<Vec<CustomServiceResponse>>, (StatusCode, String)> {
    match state.get_custom_services.get_all().await {
        Ok(services) => {
            debug!(count = services.len(), "Custom services listed");
            Ok(Json(
                services
                    .into_iter()
                    .map(CustomServiceResponse::from_entity)
                    .collect(),
            ))
        }
        Err(e) => {
            error!(error = %e, "Failed to list custom services");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn get_custom_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
) -> Result<Json<CustomServiceResponse>, (StatusCode, String)> {
    match state
        .get_custom_services
        .get_by_service_id(&service_id)
        .await
    {
        Ok(Some(cs)) => Ok(Json(CustomServiceResponse::from_entity(cs))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("Custom service '{}' not found", service_id),
        )),
        Err(e) => {
            error!(error = %e, "Failed to get custom service");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn create_custom_service(
    State(state): State<AppState>,
    Json(req): Json<CreateCustomServiceRequest>,
) -> Result<(StatusCode, Json<CustomServiceResponse>), (StatusCode, String)> {
    let category = req.category_name.as_deref().unwrap_or("Custom");

    match state
        .create_custom_service
        .execute(&req.name, category, req.domains)
        .await
    {
        Ok(cs) => Ok((
            StatusCode::CREATED,
            Json(CustomServiceResponse::from_entity(cs)),
        )),
        Err(DomainError::CustomServiceAlreadyExists(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(e) => {
            error!(error = %e, "Failed to create custom service");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn update_custom_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Json(req): Json<UpdateCustomServiceRequest>,
) -> Result<Json<CustomServiceResponse>, (StatusCode, String)> {
    match state
        .update_custom_service
        .execute(&service_id, req.name, req.category_name, req.domains)
        .await
    {
        Ok(cs) => Ok(Json(CustomServiceResponse::from_entity(cs))),
        Err(DomainError::CustomServiceNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(e) => {
            error!(error = %e, "Failed to update custom service");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_custom_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_custom_service.execute(&service_id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(DomainError::CustomServiceNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(e) => {
            error!(error = %e, "Failed to delete custom service");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
