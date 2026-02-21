use super::record_type_map::RecordTypeMapper;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ring::rand::{SecureRandom, SystemRandom};
use std::str::FromStr;

pub struct MessageBuilder;

impl MessageBuilder {
    pub fn build_query(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
    ) -> Result<Vec<u8>, DomainError> {
        let (_, bytes) = Self::build_query_with_id(domain, record_type, dnssec_ok)?;
        Ok(bytes)
    }

    pub fn build_query_with_id(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
    ) -> Result<(u16, Vec<u8>), DomainError> {
        let name = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;

        let hickory_type = RecordTypeMapper::to_hickory(record_type);
        let id = Self::secure_random_id();

        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(hickory_type);
        query.set_query_class(hickory_proto::rr::DNSClass::IN);

        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);
        message.set_edns(Self::build_edns(dnssec_ok));

        let bytes = Self::serialize_message(&message)?;
        Ok((id, bytes))
    }

    fn secure_random_id() -> u16 {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 2];
        rng.fill(&mut bytes)
            .map(|_| u16::from_be_bytes(bytes))
            .unwrap_or_else(|_| fastrand::u16(..))
    }

    fn build_edns(dnssec_ok: bool) -> Edns {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(dnssec_ok);
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
