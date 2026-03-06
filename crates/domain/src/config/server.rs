use serde::{Deserialize, Serialize};

use super::encrypted_dns::EncryptedDnsConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub dns_port: u16,

    pub web_port: u16,

    pub bind_address: String,

    #[serde(default = "default_cors_origins")]
    pub cors_allowed_origins: Vec<String>,

    pub api_key: Option<String>,

    #[serde(default)]
    pub encrypted_dns: EncryptedDnsConfig,

    #[serde(default)]
    pub proxy_protocol_enabled: bool,

    /// When `true`, mounts the Pi-hole v6 compatible API at `/api/*` and
    /// moves the Ferrous dashboard API to `/ferrous/api/*`.
    /// The frontend discovers the correct prefix via `/ferrous-config.js`.
    /// Defaults to `false` — no change in behaviour for existing deployments.
    #[serde(default)]
    pub pihole_compat: bool,
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_port: 53,
            web_port: 8080,
            bind_address: "0.0.0.0".to_string(),
            cors_allowed_origins: default_cors_origins(),
            api_key: None,
            encrypted_dns: EncryptedDnsConfig::default(),
            proxy_protocol_enabled: false,
            pihole_compat: false,
        }
    }
}
