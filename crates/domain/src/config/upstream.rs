use serde::{Deserialize, Serialize};

/// Upstream DNS server pool configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamPool {
    /// Pool name (e.g., "primary", "secondary", "cloudflare")
    pub name: String,

    /// Load balancing strategy for this pool
    pub strategy: UpstreamStrategy,

    /// Pool priority (lower number = higher priority)
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// List of DNS servers in this pool (e.g., "8.8.8.8:53")
    pub servers: Vec<String>,

    /// Optional weight for load balancing (used by some strategies)
    #[serde(default)]
    pub weight: Option<u32>,
}

/// Load balancing strategy for upstream DNS servers
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
pub enum UpstreamStrategy {
    /// Query all servers in parallel, use fastest response
    #[default]
    Parallel,
    /// Query servers in order, failover on timeout
    Failover,
    /// Distribute queries across servers based on load/latency
    Balanced,
}

impl UpstreamStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Parallel => "parallel",
            Self::Failover => "failover",
            Self::Balanced => "balanced",
        }
    }
}

fn default_priority() -> u8 {
    1
}
