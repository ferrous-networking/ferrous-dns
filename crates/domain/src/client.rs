use std::net::IpAddr;
use std::sync::Arc;

const MAC_UPDATE_THRESHOLD_SECS: i64 = 300;

const HOSTNAME_UPDATE_THRESHOLD_SECS: i64 = 3600;

#[derive(Debug, Clone)]
pub struct Client {
    pub id: Option<i64>,
    pub ip_address: IpAddr,
    pub mac_address: Option<Arc<str>>,
    pub hostname: Option<Arc<str>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub query_count: u64,
    pub last_mac_update: Option<String>,
    pub last_hostname_update: Option<String>,
    pub group_id: Option<i64>,
}

impl Client {
    pub fn new(ip_address: IpAddr) -> Self {
        Self {
            id: None,
            ip_address,
            mac_address: None,
            hostname: None,
            first_seen: None,
            last_seen: None,
            query_count: 0,
            last_mac_update: None,
            last_hostname_update: None,
            group_id: None,
        }
    }

    pub fn should_update_mac(&self) -> bool {
        self.last_mac_update.is_none()
            || self.mac_address.is_none()
            || self.is_stale(&self.last_mac_update, MAC_UPDATE_THRESHOLD_SECS)
    }

    pub fn should_update_hostname(&self) -> bool {
        self.last_hostname_update.is_none()
            || self.hostname.is_none()
            || self.is_stale(&self.last_hostname_update, HOSTNAME_UPDATE_THRESHOLD_SECS)
    }

    fn is_stale(&self, last_update: &Option<String>, threshold_secs: i64) -> bool {
        if let Some(ts) = last_update {
            if let Ok(time) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
                let update_time =
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(time, chrono::Utc);
                let now = chrono::Utc::now();
                return (now - update_time).num_seconds() > threshold_secs;
            }
        }
        true
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
