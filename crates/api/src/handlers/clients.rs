use crate::dto::{ClientResponse, ClientStatsResponse, ClientsQuery};
use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, instrument};

#[instrument(skip(state), name = "api_get_clients")]
pub async fn get_clients(
    State(state): State<AppState>,
    Query(params): Query<ClientsQuery>,
) -> Result<Json<Vec<ClientResponse>>, ApiError> {
    debug!(
        limit = params.limit,
        offset = params.offset,
        active_days = ?params.active_days,
        "Fetching clients"
    );

    let clients = if let Some(days) = params.active_days {
        state
            .clients
            .get_clients
            .get_active(days, params.limit)
            .await?
    } else {
        state
            .clients
            .get_clients
            .get_all(params.limit, params.offset)
            .await?
    };

    let response: Vec<ClientResponse> = clients
        .into_iter()
        .map(|c| ClientResponse {
            id: c.id.unwrap_or(0),
            ip_address: c.ip_address.to_string(),
            mac_address: c.mac_address.map(|s| s.to_string()),
            hostname: c.hostname.map(|s| s.to_string()),
            first_seen: c.first_seen.unwrap_or_default(),
            last_seen: c.last_seen.unwrap_or_default(),
            query_count: c.query_count,
            group_id: c.group_id,
        })
        .collect();

    debug!(count = response.len(), "Clients retrieved successfully");
    Ok(Json(response))
}

#[instrument(skip(state), name = "api_get_client_stats")]
pub async fn get_client_stats(
    State(state): State<AppState>,
) -> Result<Json<ClientStatsResponse>, ApiError> {
    debug!("Fetching client statistics");

    let stats = state.clients.get_clients.get_stats().await?;
    debug!("Client stats retrieved successfully");
    Ok(Json(ClientStatsResponse {
        total_clients: stats.total_clients,
        active_24h: stats.active_24h,
        active_7d: stats.active_7d,
        with_mac: stats.with_mac,
        with_hostname: stats.with_hostname,
    }))
}
