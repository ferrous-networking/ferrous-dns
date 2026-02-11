use super::RecordType;
use std::net::IpAddr;

/// DNS record representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Domain name
    pub domain: String,
    /// Record type
    pub record_type: RecordType,
    /// IP address
    pub address: IpAddr,
    /// Time to live in seconds
    pub ttl: u32,
}

impl DnsRecord {
    /// Create a new DNS record
    pub fn new(domain: String, record_type: RecordType, address: IpAddr, ttl: u32) -> Self {
        Self {
            domain,
            record_type,
            address,
            ttl,
        }
    }

    /// Check if record is expired based on current time
    pub fn is_expired(&self, elapsed_secs: u32) -> bool {
        elapsed_secs >= self.ttl
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self, elapsed_secs: u32) -> u32 {
        self.ttl.saturating_sub(elapsed_secs)
    }
}
