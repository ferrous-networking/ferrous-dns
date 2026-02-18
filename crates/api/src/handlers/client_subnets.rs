use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use ferrous_dns_domain::DomainError;
use tracing::{debug, error};

use crate::{
    dto::{ClientSubnetResponse, CreateClientSubnetRequest},
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/client-subnets", get(get_all_subnets))
        .route("/client-subnets", post(create_subnet))
        .route("/client-subnets/{id}", delete(delete_subnet))
}

async fn get_all_subnets(State(state): State<AppState>) -> Json<Vec<ClientSubnetResponse>> {
    match state.get_client_subnets.get_all().await {
        Ok(subnets) => {
            let mut responses = Vec::new();
            for subnet in subnets {
                let group_name = state
                    .get_groups
                    .get_by_id(subnet.group_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|g| g.name.to_string());

                responses.push(ClientSubnetResponse::from_subnet(subnet, group_name));
            }
            debug!(count = responses.len(), "Subnets retrieved successfully");
            Json(responses)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve subnets");
            Json(vec![])
        }
    }
}

async fn create_subnet(
    State(state): State<AppState>,
    Json(req): Json<CreateClientSubnetRequest>,
) -> Result<(StatusCode, Json<ClientSubnetResponse>), (StatusCode, String)> {
    match state
        .create_client_subnet
        .execute(req.subnet_cidr, req.group_id, req.comment)
        .await
    {
        Ok(subnet) => {
            if let Err(e) = state.subnet_matcher.refresh().await {
                error!(error = %e, "Failed to refresh subnet matcher");
            }

            let group_name = state
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
        Err(DomainError::InvalidCidr(msg)) => Err((StatusCode::BAD_REQUEST, msg)),
        Err(DomainError::SubnetConflict(msg)) => Err((StatusCode::CONFLICT, msg)),
        Err(DomainError::GroupNotFound(msg)) => Err((StatusCode::BAD_REQUEST, msg)),
        Err(e) => {
            error!(error = %e, "Failed to create subnet");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn delete_subnet(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_client_subnet.execute(id).await {
        Ok(()) => {
            if let Err(e) = state.subnet_matcher.refresh().await {
                error!(error = %e, "Failed to refresh subnet matcher");
            }
            Ok(StatusCode::NO_CONTENT)
        }
        Err(DomainError::SubnetNotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(e) => {
            error!(error = %e, "Failed to delete subnet");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
