use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_interval")]
    pub interval: u64,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u8,

    #[serde(default = "default_success_threshold")]
    pub success_threshold: u8,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: default_interval(),
            timeout: default_timeout(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

fn default_interval() -> u64 {
    30
}

fn default_timeout() -> u64 {
    2000
}

fn default_failure_threshold() -> u8 {
    3
}

fn default_success_threshold() -> u8 {
    2
}
