use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use ferrous_dns_domain::{Client, DomainError};
use std::net::IpAddr;

use crate::{
    dto::clients::{
        BatchDeleteRequest, ClientSuggestionsResponse, ClientsResponse, CreateClientRequest,
        PiholeClientEntry, UpdateClientRequest,
    },
    errors::PiholeApiError,
    extract::PiholeJson,
    handlers::require_id,
    state::PiholeAppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct ClientQueryParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

fn client_to_entry(c: &Client) -> Result<PiholeClientEntry, DomainError> {
    Ok(PiholeClientEntry {
        id: require_id(c.id, "client")?,
        ip: c.ip_address.to_string(),
        name: c
            .hostname
            .as_ref()
            .map(|h| h.to_string())
            .unwrap_or_default(),
        comment: None,
        groups: c.group_id.map(|g| vec![g]).unwrap_or_default(),
        date_added: c.first_seen.clone(),
        date_modified: c.last_seen.clone(),
    })
}

/// Resolves the `{client}` path segment; one that is not an IP names no client.
async fn find_client_id(state: &PiholeAppState, client: &str) -> Result<i64, DomainError> {
    let not_found = || DomainError::ClientNotFound(format!("Client {client} not found"));
    let ip: IpAddr = client.parse().map_err(|_| not_found())?;
    let found = state
        .clients
        .get_clients
        .get_by_ip(ip)
        .await?
        .ok_or_else(not_found)?;
    require_id(found.id, "client")
}

/// Pi-hole v6 GET /api/clients — list all clients.
#[utoipa::path(
    get,
    path = "/clients",
    tag = "pihole:clients",
    params(
        ("limit" = Option<u32>, Query, description = "Page size (default 1000)"),
        ("offset" = Option<u32>, Query, description = "Offset")
    ),
    responses(
        (status = 200, description = "All clients", body = ClientsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_all(
    State(state): State<PiholeAppState>,
    Query(params): Query<ClientQueryParams>,
) -> Result<Json<ClientsResponse>, PiholeApiError> {
    let limit = params.limit.unwrap_or(1000);
    let offset = params.offset.unwrap_or(0);
    let clients = state.clients.get_clients.get_all(limit, offset).await?;
    let entries: Vec<PiholeClientEntry> = clients
        .iter()
        .map(client_to_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ClientsResponse { clients: entries }))
}

/// Pi-hole v6 POST /api/clients — create client.
#[utoipa::path(
    post,
    path = "/clients",
    tag = "pihole:clients",
    request_body = CreateClientRequest,
    responses(
        (status = 201, description = "Client created", body = PiholeClientEntry),
        (status = 422, description = "Invalid IP address")
    ),
    security(("session_id" = []))
)]
pub async fn create_client(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<CreateClientRequest>,
) -> Result<impl IntoResponse, PiholeApiError> {
    let ip: IpAddr = body
        .ip
        .parse()
        .map_err(|_| DomainError::InvalidIpAddress(body.ip.clone()))?;
    let group_id = body.groups.as_ref().and_then(|g| g.first().copied());
    let result = state
        .clients
        .create_manual_client
        .execute(ip, group_id, None, None)
        .await?;
    Ok((StatusCode::CREATED, Json(client_to_entry(&result)?)))
}

/// Pi-hole v6 PUT /api/clients/:client — update client.
#[utoipa::path(
    put,
    path = "/clients/{client}",
    tag = "pihole:clients",
    params(
        ("client" = String, Path, description = "Client IP address")
    ),
    request_body = UpdateClientRequest,
    responses(
        (status = 200, description = "Client updated", body = PiholeClientEntry),
        (status = 404, description = "Client not found")
    ),
    security(("session_id" = []))
)]
pub async fn update_client(
    State(state): State<PiholeAppState>,
    Path(client_ip): Path<String>,
    PiholeJson(body): PiholeJson<UpdateClientRequest>,
) -> Result<Json<PiholeClientEntry>, PiholeApiError> {
    let id = find_client_id(&state, &client_ip).await?;
    let group_id = body.groups.as_ref().and_then(|g| g.first().copied());
    let result = state
        .clients
        .update_client
        .execute(id, None, group_id)
        .await?;
    Ok(Json(client_to_entry(&result)?))
}

/// Pi-hole v6 DELETE /api/clients/:client — delete client.
#[utoipa::path(
    delete,
    path = "/clients/{client}",
    tag = "pihole:clients",
    params(
        ("client" = String, Path, description = "Client IP address")
    ),
    responses(
        (status = 204, description = "Client deleted"),
        (status = 404, description = "Client not found")
    ),
    security(("session_id" = []))
)]
pub async fn delete_client(
    State(state): State<PiholeAppState>,
    Path(client_ip): Path<String>,
) -> Result<StatusCode, PiholeApiError> {
    let id = find_client_id(&state, &client_ip).await?;
    state.clients.delete_client.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Pi-hole v6 GET /api/clients/_suggestions — IP/hostname suggestions.
#[utoipa::path(
    get,
    path = "/clients/_suggestions",
    tag = "pihole:clients",
    responses(
        (status = 200, description = "Client suggestions", body = ClientSuggestionsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn suggestions(
    State(state): State<PiholeAppState>,
) -> Result<Json<ClientSuggestionsResponse>, PiholeApiError> {
    let clients = state.clients.get_clients.get_all(100, 0).await?;
    let suggestions: Vec<String> = clients
        .iter()
        .map(|c| {
            if let Some(h) = &c.hostname {
                format!("{} ({})", c.ip_address, h)
            } else {
                c.ip_address.to_string()
            }
        })
        .collect();
    Ok(Json(ClientSuggestionsResponse { suggestions }))
}

/// Pi-hole v6 POST /api/clients:batchDelete — batch delete clients.
#[utoipa::path(
    post,
    path = "/clients:batchDelete",
    tag = "pihole:clients",
    request_body = BatchDeleteRequest,
    responses(
        (status = 204, description = "Batch delete completed")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<BatchDeleteRequest>,
) -> Result<StatusCode, PiholeApiError> {
    for ip in body
        .items
        .iter()
        .filter_map(|item| item.parse::<IpAddr>().ok())
    {
        if let Some(c) = state.clients.get_clients.get_by_ip(ip).await? {
            state
                .clients
                .delete_client
                .execute(require_id(c.id, "client")?)
                .await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
