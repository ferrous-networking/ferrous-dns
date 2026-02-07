//! DNS Response Parser
//!
//! Parses raw DNS response bytes into structured data.
//! Centralizes the IP/CNAME extraction that was previously duplicated across
//! `resolver.rs` (2x), `parallel.rs`, and `cache_warming.rs`.
//!
//! Also centralizes the "no records found" error detection that was previously
//! done by string comparison in 5 different files.

use ferrous_dns_domain::DomainError;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};
use std::net::IpAddr;
use tracing::debug;

/// Parsed DNS response with all extracted data
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Extracted IP addresses (A and AAAA records)
    pub addresses: Vec<IpAddr>,
    /// Canonical name if CNAME record present
    pub cname: Option<String>,
    /// DNS response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)
    pub rcode: ResponseCode,
    /// Whether the response was truncated (TC bit) — caller should retry via TCP
    pub truncated: bool,
    /// Minimum TTL from answer records (useful for caching)
    pub min_ttl: Option<u32>,
    /// Raw answer records (for SOA, MX, TXT, etc. that need special handling)
    pub raw_answers: Vec<Record>,
    /// Authority section records (SOA for NODATA responses)
    pub authority_records: Vec<Record>,
    /// The parsed message (kept for server.rs to forward raw records)
    pub message: Message,
}

impl DnsResponse {
    /// True if this is a NODATA response (NOERROR with empty answers)
    pub fn is_nodata(&self) -> bool {
        self.rcode == ResponseCode::NoError && self.addresses.is_empty() && self.cname.is_none()
    }

    /// True if this is an NXDOMAIN response
    pub fn is_nxdomain(&self) -> bool {
        self.rcode == ResponseCode::NXDomain
    }

    /// True if the server returned an error (SERVFAIL, REFUSED, etc.)
    pub fn is_server_error(&self) -> bool {
        matches!(
            self.rcode,
            ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::NotImp
        )
    }
}

/// Parses raw DNS wire format responses
pub struct ResponseParser;

impl ResponseParser {
    /// Parse raw DNS response bytes into a structured DnsResponse
    ///
    /// Extracts:
    /// - IP addresses (A/AAAA records)
    /// - CNAME records
    /// - Response code (RCODE)
    /// - Truncation flag (TC bit)
    /// - Minimum TTL from answers
    /// - Authority section (for SOA in NODATA responses)
    pub fn parse(response_bytes: &[u8]) -> Result<DnsResponse, DomainError> {
        let message = Message::from_vec(response_bytes).map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to parse DNS response: {}", e))
        })?;

        let rcode = message.response_code();
        let truncated = message.truncated();

        // Extract IP addresses and CNAME from answer section
        let mut addresses = Vec::new();
        let mut cname: Option<String> = None;
        let mut min_ttl: Option<u32> = None;
        let mut raw_answers = Vec::new();

        for record in message.answers() {
            // Track minimum TTL
            let record_ttl = record.ttl();
            min_ttl = Some(min_ttl.map_or(record_ttl, |current| current.min(record_ttl)));

            match record.data() {
                RData::A(a) => {
                    addresses.push(IpAddr::V4(a.0));
                }
                RData::AAAA(aaaa) => {
                    addresses.push(IpAddr::V6(aaaa.0));
                }
                RData::CNAME(canonical) => {
                    if cname.is_none() {
                        cname = Some(canonical.to_utf8());
                        debug!(cname = %canonical.to_utf8(), "CNAME record found");
                    }
                }
                _ => {
                    // Keep raw records for MX, TXT, SOA, SRV, etc.
                    raw_answers.push(record.clone());
                }
            }
        }

        // Extract authority section (SOA records for NODATA responses)
        let authority_records: Vec<Record> = message.name_servers().iter().cloned().collect();

        debug!(
            rcode = ?rcode,
            addresses = addresses.len(),
            cname = ?cname,
            truncated = truncated,
            authority = authority_records.len(),
            "DNS response parsed"
        );

        Ok(DnsResponse {
            addresses,
            cname,
            rcode,
            truncated,
            min_ttl,
            raw_answers,
            authority_records,
            message,
        })
    }

    /// Check if a DomainError represents a server-down condition (timeout, connection error)
    /// vs a valid DNS response that happened to be an error (NXDOMAIN, SERVFAIL)
    ///
    /// This centralizes the string-based error detection that was duplicated in
    /// `pool.rs`, `balanced.rs`, `failover.rs`, `parallel.rs`, and `health.rs`.
    ///
    /// Returns `true` if the server is DOWN and we should try the next one.
    pub fn is_transport_error(error: &DomainError) -> bool {
        let error_str = error.to_string().to_lowercase();

        error_str.contains("timeout")
            || error_str.contains("timed out")
            || error_str.contains("connection refused")
            || error_str.contains("connection reset")
            || error_str.contains("connection error")
            || error_str.contains("network unreachable")
            || error_str.contains("host unreachable")
            || error_str.contains("all parallel queries failed")
            || error_str.contains("all servers failed")
            || error_str.contains("no healthy servers")
    }

    /// Convert a ResponseCode to a human-readable status string
    /// Used for query logging
    pub fn rcode_to_status(rcode: ResponseCode) -> &'static str {
        match rcode {
            ResponseCode::NoError => "NOERROR",
            ResponseCode::NXDomain => "NXDOMAIN",
            ResponseCode::ServFail => "SERVFAIL",
            ResponseCode::Refused => "REFUSED",
            ResponseCode::NotImp => "NOTIMP",
            ResponseCode::FormErr => "FORMERR",
            _ => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcode_to_status() {
        assert_eq!(
            ResponseParser::rcode_to_status(ResponseCode::NoError),
            "NOERROR"
        );
        assert_eq!(
            ResponseParser::rcode_to_status(ResponseCode::NXDomain),
            "NXDOMAIN"
        );
        assert_eq!(
            ResponseParser::rcode_to_status(ResponseCode::ServFail),
            "SERVFAIL"
        );
        assert_eq!(
            ResponseParser::rcode_to_status(ResponseCode::Refused),
            "REFUSED"
        );
    }

    #[test]
    fn test_is_transport_error() {
        assert!(ResponseParser::is_transport_error(
            &DomainError::InvalidDomainName("Timeout sending query".to_string())
        ));
        assert!(ResponseParser::is_transport_error(
            &DomainError::InvalidDomainName("Connection refused by server".to_string())
        ));
        assert!(!ResponseParser::is_transport_error(
            &DomainError::InvalidDomainName("Domain not found (NXDOMAIN)".to_string())
        ));
        assert!(!ResponseParser::is_transport_error(
            &DomainError::InvalidDomainName("SERVFAIL from upstream".to_string())
        ));
    }

    #[test]
    fn test_dns_response_states() {
        // Test is_nxdomain
        let response = DnsResponse {
            addresses: vec![],
            cname: None,
            rcode: ResponseCode::NXDomain,
            truncated: false,
            min_ttl: None,
            raw_answers: vec![],
            authority_records: vec![],
            message: Message::new(),
        };
        assert!(response.is_nxdomain());
        assert!(!response.is_nodata());
        assert!(!response.is_server_error());

        // Test is_nodata (NOERROR with no answers)
        let response = DnsResponse {
            addresses: vec![],
            cname: None,
            rcode: ResponseCode::NoError,
            truncated: false,
            min_ttl: None,
            raw_answers: vec![],
            authority_records: vec![],
            message: Message::new(),
        };
        assert!(response.is_nodata());
        assert!(!response.is_nxdomain());

        // Test is_server_error
        let response = DnsResponse {
            addresses: vec![],
            cname: None,
            rcode: ResponseCode::ServFail,
            truncated: false,
            min_ttl: None,
            raw_answers: vec![],
            authority_records: vec![],
            message: Message::new(),
        };
        assert!(response.is_server_error());
    }

    #[test]
    fn test_parse_invalid_bytes() {
        let garbage = vec![0xFF, 0x00, 0x01];
        let result = ResponseParser::parse(&garbage);
        assert!(result.is_err());
    }
}
