use ferrous_dns_domain::RecordType;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QueryEvent {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub upstream_server: Arc<str>,
    pub response_time_us: u64,
    pub success: bool,
    pub pool_name: Option<Arc<str>>,
}

impl QueryEvent {
    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn response_time_ms(&self) -> f64 {
        self.response_time_us as f64 / 1000.0
    }

    pub fn is_success(&self) -> bool {
        self.success
    }

    pub fn is_dnssec_query(&self) -> bool {
        self.record_type.is_dnssec()
    }
}
