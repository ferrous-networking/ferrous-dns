use crate::dto::{ClientResponse, ClientStatsResponse, ClientsQuery};
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_clients")]
pub async fn get_clients(
    State(state): State<AppState>,
    Query(params): Query<ClientsQuery>,
) -> Json<Vec<ClientResponse>> {
    debug!(
        limit = params.limit,
        offset = params.offset,
        active_days = ?params.active_days,
        "Fetching clients"
    );

    let clients = if let Some(days) = params.active_days {
        state.get_clients.get_active(days, params.limit).await
    } else {
        state.get_clients.get_all(params.limit, params.offset).await
    };

    match clients {
        Ok(clients) => {
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
            Json(response)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve clients");
            Json(vec![])
        }
    }
}

#[instrument(skip(state), name = "api_get_client_stats")]
pub async fn get_client_stats(State(state): State<AppState>) -> Json<ClientStatsResponse> {
    debug!("Fetching client statistics");

    match state.get_clients.get_stats().await {
        Ok(stats) => {
            debug!("Client stats retrieved successfully");
            Json(ClientStatsResponse {
                total_clients: stats.total_clients,
                active_24h: stats.active_24h,
                active_7d: stats.active_7d,
                with_mac: stats.with_mac,
                with_hostname: stats.with_hostname,
            })
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve client stats");
            Json(ClientStatsResponse {
                total_clients: 0,
                active_24h: 0,
                active_7d: 0,
                with_mac: 0,
                with_hostname: 0,
            })
        }
    }
}
