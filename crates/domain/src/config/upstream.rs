use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamPool {
    pub name: String,

    pub strategy: UpstreamStrategy,

    #[serde(default = "default_priority")]
    pub priority: u8,

    pub servers: Vec<String>,

    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
pub enum UpstreamStrategy {
    #[default]
    Parallel,

    Failover,

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

impl std::fmt::Display for UpstreamStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parallel => f.write_str("Parallel"),
            Self::Failover => f.write_str("Failover"),
            Self::Balanced => f.write_str("Balanced"),
        }
    }
}

fn default_priority() -> u8 {
    1
}
