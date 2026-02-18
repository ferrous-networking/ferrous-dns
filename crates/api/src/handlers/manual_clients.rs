use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;
use tracing::error;

use crate::{
    dto::{ClientResponse, CreateManualClientRequest},
    state::AppState,
};

pub async fn create_manual_client(
    State(state): State<AppState>,
    Json(req): Json<CreateManualClientRequest>,
) -> Result<(StatusCode, Json<ClientResponse>), (StatusCode, String)> {
    
    let ip_address = req.ip_address.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid IP address format".to_string(),
        )
    })?;

    match state
        .create_manual_client
        .execute(ip_address, req.group_id, req.hostname, req.mac_address)
        .await
    {
        Ok(client) => Ok((
            StatusCode::CREATED,
            Json(ClientResponse {
                id: client.id.unwrap_or(0),
                ip_address: client.ip_address.to_string(),
                mac_address: client.mac_address.map(|s| s.to_string()),
                hostname: client.hostname.map(|s| s.to_string()),
                first_seen: client.first_seen.unwrap_or_default(),
                last_seen: client.last_seen.unwrap_or_default(),
                query_count: client.query_count,
                group_id: client.group_id,
            }),
        )),
        Err(DomainError::GroupNotFound(msg)) => Err((StatusCode::BAD_REQUEST, msg)),
        Err(e) => {
            error!(error = %e, "Failed to create manual client");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

pub async fn delete_manual_client(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.delete_client.execute(id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(DomainError::NotFound(msg)) | Err(DomainError::ClientNotFound(msg)) => {
            Err((StatusCode::NOT_FOUND, msg))
        }
        Err(e) => {
            error!(error = %e, "Failed to delete client");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
