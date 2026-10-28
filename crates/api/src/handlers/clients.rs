use crate::dto::{ClientResponse, ClientStatsResponse, ClientsQuery, PaginatedClients};
use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::{debug, instrument};

/// Upper bound on how many clients a single listing request may return.
const MAX_CLIENTS_LIMIT: u32 = 1_000;

#[utoipa::path(
    get,
    path = "/clients",
    tag = "clients",
    params(ClientsQuery),
    responses(
        (status = 200, description = "One page of clients, newest first", body = PaginatedClients),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
#[instrument(skip(state), name = "api_get_clients")]
pub async fn get_clients(
    State(state): State<AppState>,
    Query(params): Query<ClientsQuery>,
) -> Result<Json<PaginatedClients>, ApiError> {
    debug!(
        limit = params.limit,
        offset = params.offset,
        active_days = ?params.active_days,
        "Fetching clients"
    );

    let limit = params.limit.clamp(1, MAX_CLIENTS_LIMIT);
    let (clients, total) = state
        .clients
        .get_clients
        .get_paged(limit, params.offset, params.active_days)
        .await?;

    let data: Vec<ClientResponse> = clients.into_iter().map(ClientResponse::from).collect();

    debug!(count = data.len(), total, "Clients retrieved successfully");
    Ok(Json(PaginatedClients {
        data,
        total,
        limit,
        offset: params.offset,
    }))
}

#[utoipa::path(
    get,
    path = "/clients/stats",
    tag = "clients",
    responses(
        (status = 200, description = "Aggregated client statistics", body = ClientStatsResponse),
        (status = 500, description = "Internal error"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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
