use serde::{Deserialize, Serialize};

/// Health check configuration for upstream DNS servers
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    /// Interval between health checks in seconds (default: 30)
    #[serde(default = "default_interval")]
    pub interval: u64,

    /// Health check timeout in milliseconds (default: 2000)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Number of consecutive failures before marking server as unhealthy (default: 3)
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u8,

    /// Number of consecutive successes before marking server as healthy (default: 2)
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
