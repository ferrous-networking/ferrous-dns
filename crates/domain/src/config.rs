use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub id: i64,
    pub upstream_dns: Vec<IpAddr>,
    pub cache_enabled: bool,
    pub cache_ttl_seconds: i64,
    pub blocklist_enabled: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            id: 1,
            upstream_dns: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            cache_enabled: true,
            cache_ttl_seconds: 3600,
            blocklist_enabled: true,
        }
    }
}
