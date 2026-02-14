use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct TimelineBucket {
    pub timestamp: String,
    pub total: u64,
    pub blocked: u64,
    pub unblocked: u64,
}

#[derive(Serialize, Debug)]
pub struct TimelineResponse {
    pub buckets: Vec<TimelineBucket>,
    pub period: String,
    pub granularity: String,
    pub total_buckets: usize,
}

#[derive(Deserialize, Debug)]
pub struct TimelineQuery {
    #[serde(default = "default_period")]
    pub period: String,
    #[serde(default = "default_granularity")]
    pub granularity: String,
}

fn default_period() -> String {
    "24h".to_string()
}

fn default_granularity() -> String {
    "hour".to_string()
}
