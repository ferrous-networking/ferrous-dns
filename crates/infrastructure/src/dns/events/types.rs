use ferrous_dns_domain::RecordType;
use std::sync::Arc;

/// Event emitted for every DNS query that goes to an upstream server.
///
/// This event represents a single DNS query made by the resolver to an upstream
/// DNS server (e.g., 8.8.8.8, 1.1.1.1). These events are used for comprehensive
/// query logging, including DNSSEC validation queries (DS, DNSKEY, RRSIG).
///
/// ## Fields
///
/// - `domain`: The domain being queried (e.g., "google.com")
/// - `record_type`: The DNS record type (A, AAAA, DS, DNSKEY, etc.)
/// - `upstream_server`: The upstream server address (e.g., "8.8.8.8:53")
/// - `response_time_us`: Response time in microseconds
/// - `success`: Whether the query returned valid data
///
/// ## Size
///
/// This struct is designed to be small (~48 bytes) for efficient channel transmission:
/// - `domain`: 16 bytes (Arc<str>)
/// - `record_type`: 4 bytes (enum)
/// - `upstream_server`: 24 bytes (String)
/// - `response_time_us`: 8 bytes (u64)
/// - `success`: 1 byte (bool)
///
/// ## Clone Cost
///
/// Cloning is cheap due to Arc<str> - only increments reference count.
#[derive(Debug, Clone)]
pub struct QueryEvent {
    /// Domain being queried (Arc for cheap cloning)
    pub domain: Arc<str>,

    /// DNS record type (A, AAAA, DS, DNSKEY, RRSIG, etc.)
    pub record_type: RecordType,

    /// Upstream server that handled the query (e.g., "8.8.8.8:53")
    pub upstream_server: String,

    /// Query response time in microseconds
    pub response_time_us: u64,

    /// Whether the query returned valid data (true) or failed (false)
    pub success: bool,
}

impl QueryEvent {
    /// Create a new query event
    pub fn new(
        domain: impl Into<Arc<str>>,
        record_type: RecordType,
        upstream_server: String,
        response_time_us: u64,
        success: bool,
    ) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            upstream_server,
            response_time_us,
            success,
        }
    }

    /// Get the domain
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get response time in milliseconds
    pub fn response_time_ms(&self) -> f64 {
        self.response_time_us as f64 / 1000.0
    }

    /// Check if query was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Check if this is a DNSSEC query
    pub fn is_dnssec_query(&self) -> bool {
        self.record_type.is_dnssec()
    }
}
