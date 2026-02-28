use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::DomainError;

use crate::{
    dto::{ClientResponse, CreateManualClientRequest, UpdateClientRequest},
    errors::ApiError,
    state::AppState,
};

pub async fn create_manual_client(
    State(state): State<AppState>,
    Json(req): Json<CreateManualClientRequest>,
) -> Result<(StatusCode, Json<ClientResponse>), ApiError> {
    let ip_address = req.ip_address.parse().map_err(|_| {
        ApiError(DomainError::InvalidIpAddress(
            "Invalid IP address format".to_string(),
        ))
    })?;

    let client = state
        .clients
        .create_manual_client
        .execute(ip_address, req.group_id, req.hostname, req.mac_address)
        .await?;

    Ok((
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
    ))
}

pub async fn update_manual_client(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateClientRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    let client = state
        .clients
        .update_client
        .execute(id, req.hostname, req.group_id)
        .await?;

    Ok(Json(ClientResponse {
        id: client.id.unwrap_or(0),
        ip_address: client.ip_address.to_string(),
        mac_address: client.mac_address.map(|s| s.to_string()),
        hostname: client.hostname.map(|s| s.to_string()),
        first_seen: client.first_seen.unwrap_or_default(),
        last_seen: client.last_seen.unwrap_or_default(),
        query_count: client.query_count,
        group_id: client.group_id,
    }))
}

pub async fn delete_manual_client(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.clients.delete_client.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
