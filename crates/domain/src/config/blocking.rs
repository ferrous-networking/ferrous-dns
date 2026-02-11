use serde::{Deserialize, Serialize};

/// Ad-blocking and domain filtering configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockingConfig {
    /// Enable ad-blocking (default: true)
    pub enabled: bool,

    /// Custom domains to block (user-defined blocklist)
    #[serde(default)]
    pub custom_blocked: Vec<String>,

    /// Domains to allow even if in blocklists (whitelist)
    #[serde(default)]
    pub whitelist: Vec<String>,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_blocked: vec![],
            whitelist: vec![],
        }
    }
}
