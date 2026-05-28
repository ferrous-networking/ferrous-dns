use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::{debug, error};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::{ClientSubnetResponse, CreateClientSubnetRequest},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_subnets, create_subnet))
        .routes(routes!(delete_subnet))
}

#[utoipa::path(
    get,
    path = "/client-subnets",
    tag = "client_subnets",
    responses(
        (status = 200, description = "All client subnets", body = [ClientSubnetResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/client-subnets",
    tag = "client_subnets",
    request_body = CreateClientSubnetRequest,
    responses(
        (status = 201, description = "Subnet created", body = ClientSubnetResponse),
        (status = 409, description = "Subnet conflict"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    delete,
    path = "/client-subnets/{id}",
    tag = "client_subnets",
    params(("id" = i64, Path, description = "Subnet ID")),
    responses(
        (status = 204, description = "Subnet deleted"),
        (status = 404, description = "Subnet not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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
