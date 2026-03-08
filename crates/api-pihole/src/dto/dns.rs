use serde::{Deserialize, Serialize};

/// Pi-hole v6 GET /api/dns/blocking response.
#[derive(Debug, Serialize)]
pub struct BlockingStatusResponse {
    pub blocking: bool,
    pub timer: Option<u64>,
}

/// Pi-hole v6 POST /api/dns/blocking request.
#[derive(Debug, Deserialize)]
pub struct SetBlockingRequest {
    pub blocking: bool,
    /// Optional timer in seconds — re-enables blocking after this period.
    pub timer: Option<u64>,
}
