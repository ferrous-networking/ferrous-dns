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
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

pub(crate) const CLIENT_SELECT: &str = "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients";

pub(crate) const CLIENT_SELECT_BY_IP: &str = "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients WHERE ip_address = ?";

pub(crate) const CLIENT_SELECT_BY_ID: &str = "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients WHERE id = ?";

pub(crate) const CLIENT_SELECT_ALL: &str = "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients ORDER BY last_seen DESC LIMIT ? OFFSET ?";

pub(crate) const CLIENT_SELECT_ACTIVE: &str = "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients WHERE last_seen > datetime('now', ?) ORDER BY last_seen DESC LIMIT ?";

pub(crate) const CLIENT_SELECT_NEEDS_MAC_UPDATE: &str =
    "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients WHERE (last_mac_update IS NULL
                         OR last_mac_update < datetime('now', '-5 minutes'))
     AND last_seen > datetime('now', '-1 day')
     ORDER BY last_seen DESC LIMIT ?";

pub(crate) const CLIENT_SELECT_NEEDS_HOSTNAME_UPDATE: &str =
    "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id
     FROM clients WHERE (last_hostname_update IS NULL
                         OR last_hostname_update < datetime('now', '-1 hour'))
     AND last_seen > datetime('now', '-7 days')
     ORDER BY last_seen DESC LIMIT ?";

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
