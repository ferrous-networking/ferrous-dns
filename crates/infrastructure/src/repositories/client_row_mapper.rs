use ferrous_dns_domain::Client;
use std::sync::Arc;

pub(crate) type ClientRow = (
    i64,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
);

pub(crate) const CLIENT_SELECT: &str = "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            datetime(last_mac_update) as last_mac_update,
            datetime(last_hostname_update) as last_hostname_update,
            group_id
     FROM clients";

pub(crate) fn row_to_client(row: ClientRow) -> Option<Client> {
    let (
        id,
        ip,
        mac,
        hostname,
        first_seen,
        last_seen,
        query_count,
        last_mac_update,
        last_hostname_update,
        group_id,
    ) = row;

    Some(Client {
        id: Some(id),
        ip_address: ip.parse().ok()?,
        mac_address: mac.map(|s| Arc::from(s.as_str())),
        hostname: hostname.map(|s| Arc::from(s.as_str())),
        first_seen: Some(first_seen),
        last_seen: Some(last_seen),
        query_count: query_count as u64,
        last_mac_update,
        last_hostname_update,
        group_id,
    })
}
