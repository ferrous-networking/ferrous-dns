use super::record_type_map::RecordTypeMapper;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::str::FromStr;

pub struct MessageBuilder;

impl MessageBuilder {
    pub fn build_query(domain: &str, record_type: &RecordType) -> Result<Vec<u8>, DomainError> {
        let name = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;

        let hickory_type = RecordTypeMapper::to_hickory(record_type);

        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(hickory_type);
        query.set_query_class(hickory_proto::rr::DNSClass::IN);

        let mut message = Message::new(fastrand::u16(..), MessageType::Query, OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);
        message.set_edns(Self::default_edns());

        Self::serialize_message(&message)
    }

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
        message.set_edns(Self::default_edns());

        let bytes = Self::serialize_message(&message)?;
        Ok((id, bytes))
    }

    fn default_edns() -> Edns {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        edns.set_version(0);
        edns
    }

    fn serialize_message(message: &Message) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);

        message.emit(&mut encoder).map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to serialize DNS message: {}", e))
        })?;

        Ok(buf)
    }
}
