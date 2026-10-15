use std::net::IpAddr;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ferrous_dns_domain::{Client, ClientSubnet, DomainError};

use crate::{
    crud::{
        delete_reply, first_group, record, reject_unsafe_item, reply_comment, request_comment,
        require_items, to_ftl_group_id, unix_seconds, write_status, CrudError, DEFAULT_GROUP_ID,
    },
    devices::{group_devices, Device},
    dto::clients::{
        ClientSuggestion, ClientSuggestionsQuery, ClientSuggestionsResponse, ClientsResponse,
        ClientsWriteResponse, CreateClientRequest, PiholeClientEntry, UpdateClientRequest,
    },
    dto::crud::{BatchDeleteItem, Processed},
    extract::{PiholeJson, UriItem},
    handlers::require_id,
    state::PiholeAppState,
};

/// What FTL also accepts as a client and Ferrous cannot store.
const NOT_AN_ADDRESS_OR_SUBNET: &str =
    "Ferrous identifies clients by IP address or subnet only, not by MAC address, hostname or interface";

/// network.c's default for `?count=`.
const DEFAULT_SUGGESTIONS: u32 = 50;

/// Reads every row of the clients table.
const ALL_CLIENTS: u32 = u32::MAX;

/// What a client item names: one address, or a subnet in its canonical form.
enum ClientItem {
    Address(IpAddr),
    Subnet(String),
    Other,
}

impl ClientItem {
    fn parse(item: &str) -> Self {
        if let Ok(ip) = item.parse() {
            return Self::Address(ip);
        }
        match ClientSubnet::parse_cidr(item) {
            Ok(network) => Self::Subnet(network.to_string()),
            Err(_) => Self::Other,
        }
    }
}

fn client_to_entry(c: &Client) -> Result<PiholeClientEntry, DomainError> {
    Ok(PiholeClientEntry {
        client: c.ip_address.to_string(),
        name: c.hostname.as_deref().unwrap_or_default().to_string(),
        comment: reply_comment(c.comment.as_ref()),
        groups: c.group_id.map(to_ftl_group_id).into_iter().collect(),
        id: require_id(c.id, "client")?,
        date_added: unix_seconds(c.first_seen.as_deref()),
        date_modified: unix_seconds(c.last_seen.as_deref()),
    })
}

/// FTL keeps a subnet in the clients table with its CIDR as the client.
fn subnet_to_entry(s: &ClientSubnet) -> Result<PiholeClientEntry, DomainError> {
    Ok(PiholeClientEntry {
        client: s.subnet_cidr.to_string(),
        name: String::new(),
        comment: reply_comment(s.comment.as_ref()),
        groups: vec![to_ftl_group_id(s.group_id)],
        id: require_id(s.id, "client subnet")?,
        date_added: unix_seconds(s.created_at.as_deref()),
        date_modified: unix_seconds(s.updated_at.as_deref()),
    })
}

/// The stored subnet `cidr` (canonical) names, if any.
async fn find_subnet(
    state: &PiholeAppState,
    cidr: &str,
) -> Result<Option<ClientSubnet>, DomainError> {
    Ok(state
        .clients
        .get_client_subnets
        .get_all()
        .await?
        .into_iter()
        .find(|s| s.subnet_cidr.as_ref() == cidr))
}

/// The clients `item` names, or all of them for an empty item: the address
/// clients, then the subnets, each in id order like FTL's table. Address and
/// subnet ids come from separate sequences.
async fn read_clients(
    state: &PiholeAppState,
    item: &str,
) -> Result<Vec<PiholeClientEntry>, DomainError> {
    if item.is_empty() {
        let mut all = state.clients.get_clients.get_all(ALL_CLIENTS, 0).await?;
        all.sort_by_key(|c| c.id);
        let mut subnets = state.clients.get_client_subnets.get_all().await?;
        subnets.sort_by_key(|s| s.id);
        return all
            .iter()
            .map(client_to_entry)
            .chain(subnets.iter().map(subnet_to_entry))
            .collect();
    }
    match ClientItem::parse(item) {
        ClientItem::Address(ip) => state
            .clients
            .get_clients
            .get_by_ip(ip)
            .await?
            .iter()
            .map(client_to_entry)
            .collect(),
        ClientItem::Subnet(cidr) => find_subnet(state, &cidr)
            .await?
            .iter()
            .map(subnet_to_entry)
            .collect(),
        ClientItem::Other => Ok(Vec::new()),
    }
}

/// Whether a write may replace a client that exists: a PUT may, a POST of a
/// subnet that exists is FTL's duplicate.
#[derive(Clone, Copy, PartialEq)]
enum Write {
    Create,
    Replace,
}

/// Adds `item`, or updates it. An address is updated when the resolver
/// already knows it, even on a POST: the clients table also holds every
/// client that has queried, so an existing row is not a duplicate. The group
/// changes only when one is given.
async fn write_client(
    state: &PiholeAppState,
    item: &str,
    group_id: Option<i64>,
    comment: Option<String>,
    write: Write,
) -> Result<(), DomainError> {
    match ClientItem::parse(item) {
        ClientItem::Address(ip) => {
            let client = state
                .clients
                .create_manual_client
                .execute(ip, group_id, None, None)
                .await?;
            let id = require_id(client.id, "client")?;
            state.clients.set_client_comment.execute(id, comment).await
        }
        ClientItem::Subnet(cidr) => match find_subnet(state, &cidr).await? {
            Some(_) if write == Write::Create => {
                Err(DomainError::AlreadyExists(format!("Subnet {cidr}")))
            }
            Some(existing) => {
                let id = require_id(existing.id, "client subnet")?;
                let group_id = group_id.unwrap_or(existing.group_id);
                state
                    .clients
                    .update_client_subnet
                    .execute(id, group_id, comment)
                    .await
                    .map(drop)
            }
            None => state
                .clients
                .create_client_subnet
                .execute(cidr, group_id.unwrap_or(DEFAULT_GROUP_ID), comment)
                .await
                .map(drop),
        },
        ClientItem::Other => Err(DomainError::InvalidInput(
            NOT_AN_ADDRESS_OR_SUBNET.to_string(),
        )),
    }
}

/// Deletes the clients named in `items`, returning how many went.
async fn delete_clients(state: &PiholeAppState, items: &[String]) -> Result<usize, DomainError> {
    let mut deleted = 0;
    for item in items {
        match ClientItem::parse(item) {
            ClientItem::Address(ip) => {
                if let Some(client) = state.clients.get_clients.get_by_ip(ip).await? {
                    let id = require_id(client.id, "client")?;
                    state.clients.delete_client.execute(id).await?;
                    deleted += 1;
                }
            }
            ClientItem::Subnet(cidr) => {
                if let Some(subnet) = find_subnet(state, &cidr).await? {
                    let id = require_id(subnet.id, "client subnet")?;
                    state.clients.delete_client_subnet.execute(id).await?;
                    deleted += 1;
                }
            }
            ClientItem::Other => {}
        }
    }
    Ok(deleted)
}

fn write_reply(
    status: StatusCode,
    clients: Vec<PiholeClientEntry>,
    processed: Processed,
) -> Response {
    (status, Json(ClientsWriteResponse { clients, processed })).into_response()
}

/// A device as network.c's client suggestions list it: its addresses and
/// distinct names, comma-joined.
fn into_suggestion(device: Device<'_>) -> ClientSuggestion {
    let joined = |values: Vec<String>| (!values.is_empty()).then(|| values.join(","));
    let mut names: Vec<String> = Vec::new();
    for name in device.clients.iter().filter_map(|c| c.hostname.as_deref()) {
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    ClientSuggestion {
        last_query: device.last_query(),
        addresses: joined(
            device
                .clients
                .iter()
                .map(|c| c.ip_address.to_string())
                .collect(),
        ),
        names: joined(names),
        hwaddr: Some(device.hwaddr),
        mac_vendor: None,
    }
}

/// Pi-hole v6 GET /api/clients — list all clients.
#[utoipa::path(
    get,
    path = "/clients",
    tag = "pihole:clients",
    responses(
        (status = 200, description = "All clients", body = ClientsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn list_all(
    State(state): State<PiholeAppState>,
) -> Result<Json<ClientsResponse>, CrudError> {
    let clients = read_clients(&state, "").await?;
    Ok(Json(ClientsResponse { clients }))
}

/// Pi-hole v6 POST /api/clients — add one client or several.
#[utoipa::path(
    post,
    path = "/clients",
    tag = "pihole:clients",
    request_body = CreateClientRequest,
    responses(
        (status = 201, description = "The last client as stored, and what was processed", body = ClientsWriteResponse),
        (status = 400, description = "No client, or every client failed")
    ),
    security(("session_id" = []))
)]
pub async fn create_client(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<CreateClientRequest>,
) -> Result<Response, CrudError> {
    let items = require_items(
        body.client,
        "Invalid request: No valid \"client\" in payload (must be either string or array)",
    )?;
    for item in &items {
        reject_unsafe_item(item, false)?;
    }
    let group_id = first_group(body.groups.as_deref());
    let comment = request_comment(body.comment);

    let mut processed = Processed::default();
    for item in &items {
        let result = write_client(&state, item, group_id, comment.clone(), Write::Create).await;
        record(&mut processed, item, result)?;
    }

    let status = write_status(&processed, StatusCode::CREATED)?;
    let last = items.last().map(String::as_str).unwrap_or_default();
    let clients = read_clients(&state, last).await?;
    Ok(write_reply(status, clients, processed))
}

/// Pi-hole v6 GET /api/clients/:client — the client, if it exists.
#[utoipa::path(
    get,
    path = "/clients/{client}",
    tag = "pihole:clients",
    params(
        ("client" = String, Path, description = "Client IP address")
    ),
    responses(
        (status = 200, description = "The client, or an empty list", body = ClientsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_client(
    State(state): State<PiholeAppState>,
    UriItem(item): UriItem,
) -> Result<Json<ClientsResponse>, CrudError> {
    let clients = read_clients(&state, &item).await?;
    Ok(Json(ClientsResponse { clients }))
}

/// Pi-hole v6 PUT /api/clients/:client — add or update a client.
#[utoipa::path(
    put,
    path = "/clients/{client}",
    tag = "pihole:clients",
    params(
        ("client" = String, Path, description = "Client IP address")
    ),
    request_body = UpdateClientRequest,
    responses(
        (status = 200, description = "The client as stored, and what was processed", body = ClientsWriteResponse),
        (status = 400, description = "Not an IP address, or the write failed")
    ),
    security(("session_id" = []))
)]
pub async fn update_client(
    State(state): State<PiholeAppState>,
    UriItem(item): UriItem,
    PiholeJson(body): PiholeJson<UpdateClientRequest>,
) -> Result<Response, CrudError> {
    reject_unsafe_item(&item, false)?;

    let mut processed = Processed::default();
    let result = write_client(
        &state,
        &item,
        first_group(body.groups.as_deref()),
        request_comment(body.comment),
        Write::Replace,
    )
    .await;
    record(&mut processed, &item, result)?;

    let status = write_status(&processed, StatusCode::OK)?;
    let clients = read_clients(&state, &item).await?;
    Ok(write_reply(status, clients, processed))
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
    UriItem(item): UriItem,
) -> Result<Response, CrudError> {
    let deleted = delete_clients(&state, &[item])
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}

/// Pi-hole v6 GET /api/clients/_suggestions — devices the resolver has seen.
#[utoipa::path(
    get,
    path = "/clients/_suggestions",
    tag = "pihole:clients",
    params(
        ("count" = Option<u32>, Query, description = "Most devices to return (default 50)")
    ),
    responses(
        (status = 200, description = "Devices, most recently active first", body = ClientSuggestionsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn suggestions(
    State(state): State<PiholeAppState>,
    Query(query): Query<ClientSuggestionsQuery>,
) -> Result<Json<ClientSuggestionsResponse>, CrudError> {
    let count = query.count.unwrap_or(DEFAULT_SUGGESTIONS);
    let clients = state.clients.get_clients.get_all(ALL_CLIENTS, 0).await?;
    Ok(Json(ClientSuggestionsResponse {
        clients: group_devices(&clients)
            .into_iter()
            .take(count as usize)
            .map(into_suggestion)
            .collect(),
    }))
}

/// Pi-hole v6 POST /api/clients:batchDelete — delete `[{item}]`.
#[utoipa::path(
    post,
    path = "/clients:batchDelete",
    tag = "pihole:clients",
    request_body = Vec<BatchDeleteItem>,
    responses(
        (status = 204, description = "Clients deleted"),
        (status = 404, description = "Nothing matched")
    ),
    security(("session_id" = []))
)]
pub async fn batch_delete(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<Vec<BatchDeleteItem>>,
) -> Result<Response, CrudError> {
    let items: Vec<String> = body.into_iter().map(|entry| entry.item).collect();
    let deleted = delete_clients(&state, &items)
        .await
        .map_err(CrudError::from_delete)?;
    Ok(delete_reply(deleted))
}
