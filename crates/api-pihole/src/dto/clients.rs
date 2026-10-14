use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::dto::crud::{Processed, StringOrArray};

/// Pi-hole v6 client entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeClientEntry {
    /// The client's IP address, or a subnet in CIDR form.
    pub client: String,
    /// Its hostname; empty when unknown or for a subnet, as FTL sends it.
    pub name: String,
    /// Null when there is none.
    pub comment: Option<String>,
    /// FTL group ids; the default group is 0, and an empty list means none
    /// was assigned.
    pub groups: Vec<i64>,
    pub id: i64,
    /// Unix seconds: when the client was added or first seen.
    pub date_added: i64,
    /// Unix seconds: its last change, which includes its last query.
    pub date_modified: i64,
}

/// Pi-hole v6 POST /api/clients request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateClientRequest {
    /// One IP address or subnet, or an array of them.
    pub client: Option<StringOrArray>,
    pub comment: Option<String>,
    /// FTL group ids; only the first is assigned.
    pub groups: Option<Vec<i64>>,
}

/// Pi-hole v6 PUT /api/clients/:client request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClientRequest {
    /// Replaces the stored comment; none clears it, as in FTL.
    pub comment: Option<String>,
    /// FTL group ids; only the first is assigned, and the group stays as it
    /// is when omitted.
    pub groups: Option<Vec<i64>>,
}

/// Pi-hole v6 clients list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientsResponse {
    pub clients: Vec<PiholeClientEntry>,
}

/// Pi-hole v6 POST/PUT client response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientsWriteResponse {
    pub clients: Vec<PiholeClientEntry>,
    pub processed: Processed,
}

/// `?count=` of GET /api/clients/_suggestions.
#[derive(Debug, Deserialize)]
pub struct ClientSuggestionsQuery {
    pub count: Option<u32>,
}

/// Pi-hole v6 GET /api/clients/_suggestions response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSuggestionsResponse {
    pub clients: Vec<ClientSuggestion>,
}

/// One device the resolver has seen, as FTL's network table describes it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSuggestion {
    /// MAC address, or FTL's `ip-<address>` when none is known.
    pub hwaddr: Option<String>,
    /// Always null: Ferrous has no vendor database.
    #[serde(rename = "macVendor")]
    pub mac_vendor: Option<String>,
    /// Unix seconds of the device's last query.
    #[serde(rename = "lastQuery")]
    pub last_query: i64,
    /// Comma-separated IP addresses.
    pub addresses: Option<String>,
    /// Comma-separated hostnames, if any are known.
    pub names: Option<String>,
}
