use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Client {
    pub id: Option<i64>,
    pub ip_address: IpAddr,
    pub mac_address: Option<Arc<str>>,
    pub hostname: Option<Arc<str>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub query_count: u64,
    pub last_mac_update: Option<i64>,
    pub last_hostname_update: Option<i64>,
    pub group_id: Option<i64>,
    pub comment: Option<Arc<str>>,
}

/// Where a client's hostname came from. A name set by hand is never
/// replaced by an automatic source, and the name a device announces over
/// mDNS outranks its PTR record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameSource {
    /// The hostname sync's PTR lookup.
    Ptr,
    /// The name the device announces for itself over mDNS.
    Mdns,
    /// Typed in through the dashboard or the API.
    Manual,
}

impl HostnameSource {
    /// The value stored in `clients.hostname_source`.
    pub fn as_str(self) -> &'static str {
        match self {
            HostnameSource::Ptr => "ptr",
            HostnameSource::Mdns => "mdns",
            HostnameSource::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientStats {
    pub total_clients: u64,
    pub active_24h: u64,
    pub active_7d: u64,
    pub with_mac: u64,
    pub with_hostname: u64,
}
