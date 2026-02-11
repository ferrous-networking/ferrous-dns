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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_dns_record_creation() {
        let record = DnsRecord::new(
            "example.com".to_string(),
            RecordType::A,
            IpAddr::from_str("192.0.2.1").unwrap(),
            300,
        );

        assert_eq!(record.domain, "example.com");
        assert_eq!(record.record_type, RecordType::A);
        assert_eq!(record.ttl, 300);
    }

    #[test]
    fn test_record_expiration() {
        let record = DnsRecord::new(
            "example.com".to_string(),
            RecordType::A,
            IpAddr::from_str("192.0.2.1").unwrap(),
            300,
        );

        assert!(!record.is_expired(100));
        assert!(!record.is_expired(299));
        assert!(record.is_expired(300));
        assert!(record.is_expired(500));
    }

    #[test]
    fn test_remaining_ttl() {
        let record = DnsRecord::new(
            "example.com".to_string(),
            RecordType::A,
            IpAddr::from_str("192.0.2.1").unwrap(),
            300,
        );

        assert_eq!(record.remaining_ttl(0), 300);
        assert_eq!(record.remaining_ttl(100), 200);
        assert_eq!(record.remaining_ttl(300), 0);
        assert_eq!(record.remaining_ttl(500), 0);
    }
}
