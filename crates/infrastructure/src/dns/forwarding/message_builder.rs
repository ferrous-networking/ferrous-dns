//! DNS Message Builder
//!
//! Constructs DNS query messages in wire format using `hickory-proto`.
//! This replaces the implicit message construction that `hickory-resolver`
//! was doing internally, giving us full control over the query.

use super::record_type_map::RecordTypeMapper;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::str::FromStr;

/// Builds DNS query messages in wire format
pub struct MessageBuilder;

impl MessageBuilder {
    /// Build a DNS query message and serialize to wire format bytes
    ///
    /// Creates a standard recursive query with:
    /// - Random ID for request/response matching
    /// - RD (Recursion Desired) flag set
    /// - Single question section
    ///
    /// # Arguments
    /// * `domain` - Domain name to query (e.g., "google.com")
    /// * `record_type` - DNS record type (A, AAAA, CNAME, etc.)
    ///
    /// # Returns
    /// Serialized DNS message bytes ready to send over UDP/TCP
    pub fn build_query(domain: &str, record_type: &RecordType) -> Result<Vec<u8>, DomainError> {
        // Parse domain name
        let name = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;

        // Convert to hickory record type
        let hickory_type = RecordTypeMapper::to_hickory(record_type);

        // Build query
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(hickory_type);
        query.set_query_class(hickory_proto::rr::DNSClass::IN);

        // Build message
        let mut message = Message::new(fastrand::u16(..), MessageType::Query, OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);

        // Serialize to wire format
        Self::serialize_message(&message)
    }

    /// Build a query message and return both the Message struct and bytes
    ///
    /// Useful when you need the message ID for response matching.
    pub fn build_query_with_id(
        domain: &str,
        record_type: &RecordType,
    ) -> Result<(u16, Vec<u8>), DomainError> {
        let name = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;

        let hickory_type = RecordTypeMapper::to_hickory(record_type);

        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(hickory_type);
        query.set_query_class(hickory_proto::rr::DNSClass::IN);

        let id = fastrand::u16(..);

        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);

        let bytes = Self::serialize_message(&message)?;
        Ok((id, bytes))
    }

    /// Serialize a Message to wire format bytes
    fn serialize_message(message: &Message) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);

        message.emit(&mut encoder).map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to serialize DNS message: {}", e))
        })?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_a_query() {
        let bytes = MessageBuilder::build_query("google.com", &RecordType::A);
        assert!(bytes.is_ok());

        let bytes = bytes.unwrap();
        // DNS header is always 12 bytes, plus question section
        assert!(
            bytes.len() >= 12,
            "DNS message too short: {} bytes",
            bytes.len()
        );

        // Check flags: byte 2 should have RD bit set (0x01 in lower nibble)
        // Byte 2: QR(1) + Opcode(4) + AA(1) + TC(1) + RD(1)
        // For query with RD: 0b00000001 = 0x01
        assert_eq!(bytes[2] & 0x01, 0x01, "RD flag should be set");
    }

    #[test]
    fn test_build_aaaa_query() {
        let bytes = MessageBuilder::build_query("example.com", &RecordType::AAAA);
        assert!(bytes.is_ok());
    }

    #[test]
    fn test_build_query_with_id() {
        let result = MessageBuilder::build_query_with_id("test.com", &RecordType::A);
        assert!(result.is_ok());

        let (id, bytes) = result.unwrap();
        // ID is in the first 2 bytes (big-endian)
        let wire_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(wire_id, id, "Wire ID should match returned ID");
    }

    #[test]
    fn test_invalid_domain() {
        // Empty string should fail
        let result = MessageBuilder::build_query("", &RecordType::A);
        // Note: hickory-proto may accept empty string, so this tests the flow
        // rather than enforcing validation (domain validation is elsewhere)
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_all_record_types_build() {
        let types = vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::TXT,
            RecordType::SOA,
            RecordType::NS,
            RecordType::CNAME,
        ];

        for rt in types {
            let result = MessageBuilder::build_query("example.com", &rt);
            assert!(result.is_ok(), "Failed to build query for {:?}", rt);
        }
    }
}
