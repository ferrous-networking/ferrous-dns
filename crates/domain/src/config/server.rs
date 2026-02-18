use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub dns_port: u16,

    pub web_port: u16,

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
