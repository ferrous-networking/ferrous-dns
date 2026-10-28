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
    Option<String>,
);

macro_rules! client_select {
    ($($tail:tt)*) => {
        concat!(
            "SELECT id, ip_address, mac_address, hostname,
            datetime(first_seen) as first_seen,
            datetime(last_seen) as last_seen,
            query_count,
            CAST(strftime('%s', last_mac_update) AS INTEGER) as last_mac_update,
            CAST(strftime('%s', last_hostname_update) AS INTEGER) as last_hostname_update,
            group_id,
            comment
     FROM clients",
            $($tail)*
        )
    };
}

pub(crate) const CLIENT_SELECT_BY_IP: &str = client_select!(" WHERE ip_address = ?");

pub(crate) const CLIENT_SELECT_BY_ID: &str = client_select!(" WHERE id = ?");

pub(crate) const CLIENT_SELECT_BY_GROUP: &str =
    client_select!(" WHERE group_id = ? ORDER BY last_seen DESC");

// `id` breaks ties, so clients seen in the same second keep one order across pages.
pub(crate) const CLIENT_SELECT_ALL: &str =
    client_select!(" ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?");

pub(crate) const CLIENT_COUNT_ALL: &str = "SELECT COUNT(*) FROM clients";

pub(crate) const CLIENT_SELECT_ACTIVE: &str = client_select!(
    " WHERE last_seen > datetime('now', ?) ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?"
);

/// Counts the rows [`CLIENT_SELECT_ACTIVE`] pages through.
pub(crate) const CLIENT_COUNT_ACTIVE: &str =
    "SELECT COUNT(*) FROM clients WHERE last_seen > datetime('now', ?)";

pub(crate) const CLIENT_SELECT_NEEDS_MAC_UPDATE: &str = client_select!(
    " WHERE (last_mac_update IS NULL
                         OR last_mac_update < datetime('now', '-5 minutes'))
     AND last_seen > datetime('now', '-1 day')
     ORDER BY last_seen DESC LIMIT ?"
);

/// Clients whose name the PTR sync may replace: never one named by hand, and
/// one named over mDNS only once the device has gone a day without
/// announcing it again.
macro_rules! ptr_may_rename {
    () => {
        "(hostname_source IS NULL OR hostname_source = 'ptr'
          OR (hostname_source = 'mdns' AND last_hostname_update < datetime('now', '-1 day')))"
    };
}

pub(crate) const CLIENT_SELECT_NEEDS_HOSTNAME_UPDATE: &str = client_select!(
    " WHERE (last_hostname_update IS NULL
                         OR last_hostname_update < datetime('now', '-1 hour'))
     AND ",
    ptr_may_rename!(),
    "
     AND last_seen > datetime('now', '-7 days')
     ORDER BY last_seen DESC LIMIT ?"
);

macro_rules! update_hostname {
    ($($guard:tt)*) => {
        concat!(
            "UPDATE clients SET
                 hostname = ?,
                 hostname_source = ?,
                 last_hostname_update = ?,
                 updated_at = ?
             WHERE ip_address = ?",
            $($guard)*
        )
    };
}

pub(crate) const UPDATE_HOSTNAME: &str = update_hostname!();

/// An automatic source never replaces a name set by hand.
pub(crate) const UPDATE_HOSTNAME_UNLESS_MANUAL: &str =
    update_hostname!(" AND (hostname_source IS NULL OR hostname_source <> 'manual')");

pub(crate) const UPDATE_HOSTNAME_FROM_PTR: &str = update_hostname!(" AND ", ptr_may_rename!());

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
        comment,
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
        comment: comment.map(|s| Arc::from(s.as_str())),
    })
}
