use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use tracing::error;

use crate::{
    dto::{AssignGroupRequest, ClientResponse},
    state::AppState,
};

pub async fn assign_client_to_group(
    State(state): State<AppState>,
    Path(client_id): Path<i64>,
    Json(req): Json<AssignGroupRequest>,
) -> Result<Json<ClientResponse>, (StatusCode, String)> {
    match state
        .assign_client_group
        .execute(client_id, req.group_id)
        .await
    {
        Ok(client) => Ok(Json(ClientResponse {
            id: client.id.unwrap_or(0),
            ip_address: client.ip_address.to_string(),
            mac_address: client.mac_address.map(|s| s.to_string()),
            hostname: client.hostname.map(|s| s.to_string()),
            first_seen: client.first_seen.unwrap_or_default(),
            last_seen: client.last_seen.unwrap_or_default(),
            query_count: client.query_count,
            group_id: client.group_id,
        })),
        Err(DomainError::NotFound(msg)) => Err((StatusCode::NOT_FOUND, msg)),
        Err(e @ DomainError::GroupNotFound(_)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => {
            error!(error = %e, "Failed to assign client to group");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
