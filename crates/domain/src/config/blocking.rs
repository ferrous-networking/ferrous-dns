use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockingConfig {
    pub enabled: bool,

    #[serde(default)]
    pub custom_blocked: Vec<String>,

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
