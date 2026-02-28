/// Status of an upstream DNS server.
#[derive(Debug, Clone, Copy)]
pub enum UpstreamStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Port for querying upstream DNS server health status.
pub trait UpstreamHealthPort: Send + Sync {
    fn get_all_upstream_status(&self) -> Vec<(String, UpstreamStatus)>;
}
