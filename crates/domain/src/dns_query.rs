use super::RecordType;

/// Represents a DNS query (domain + record type)
/// This is used for querying upstream DNS servers
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub domain: String,
    pub record_type: RecordType,
}

impl DnsQuery {
    pub fn new(domain: String, record_type: RecordType) -> Self {
        Self {
            domain,
            record_type,
        }
    }
}
