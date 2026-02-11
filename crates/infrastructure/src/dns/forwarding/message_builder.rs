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
