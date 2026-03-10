use ferrous_dns_application::ports;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct TimelineBucket {
    pub timestamp: String,
    pub total: u64,
    pub blocked: u64,
    pub unblocked: u64,
    pub malware_detected: u64,
}

impl From<ports::TimelineBucket> for TimelineBucket {
    fn from(b: ports::TimelineBucket) -> Self {
        Self {
            timestamp: b.timestamp,
            total: b.total,
            blocked: b.blocked,
            unblocked: b.unblocked,
            malware_detected: b.malware_detected,
        }
    }
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
