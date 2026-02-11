use serde::{Deserialize, Serialize};

/// Server configuration for DNS and Web interfaces
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// DNS server port (default: 53)
    pub dns_port: u16,

    /// Web interface port (default: 8080)
    pub web_port: u16,

    /// Bind address for all services (default: "0.0.0.0")
    pub bind_address: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_port: 53,
            web_port: 8080,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}
