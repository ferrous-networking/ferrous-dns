use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use tracing::{debug, error};

use crate::{
    dto::{ClientSubnetResponse, CreateClientSubnetRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/client-subnets", get(get_all_subnets))
        .route("/client-subnets", post(create_subnet))
        .route("/client-subnets/{id}", delete(delete_subnet))
}

async fn get_all_subnets(
    State(state): State<AppState>,
) -> Result<Json<Vec<ClientSubnetResponse>>, ApiError> {
    let subnets = state.clients.get_client_subnets.get_all().await?;
    let mut responses = Vec::new();
    for subnet in subnets {
        let group_name = state
            .groups
            .get_groups
            .get_by_id(subnet.group_id)
            .await
            .ok()
            .flatten()
            .map(|g| g.name.to_string());

        responses.push(ClientSubnetResponse::from_subnet(subnet, group_name));
    }
    debug!(count = responses.len(), "Subnets retrieved successfully");
    Ok(Json(responses))
}

async fn create_subnet(
    State(state): State<AppState>,
    Json(req): Json<CreateClientSubnetRequest>,
) -> Result<(StatusCode, Json<ClientSubnetResponse>), ApiError> {
    let subnet = state
        .clients
        .create_client_subnet
        .execute(req.subnet_cidr, req.group_id, req.comment)
        .await?;

    if let Err(e) = state.clients.subnet_matcher.refresh().await {
        error!(error = %e, "Failed to refresh subnet matcher");
    }

    let group_name = state
        .groups
        .get_groups
        .get_by_id(subnet.group_id)
        .await
        .ok()
        .flatten()
        .map(|g| g.name.to_string());

    Ok((
        StatusCode::CREATED,
        Json(ClientSubnetResponse::from_subnet(subnet, group_name)),
    ))
}

async fn delete_subnet(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.clients.delete_client_subnet.execute(id).await?;

    if let Err(e) = state.clients.subnet_matcher.refresh().await {
        error!(error = %e, "Failed to refresh subnet matcher");
    }

    Ok(StatusCode::NO_CONTENT)
}
