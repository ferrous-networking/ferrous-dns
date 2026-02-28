use bytes::Bytes;
use ferrous_dns_domain::DomainError;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub addresses: Vec<IpAddr>,

    pub cname_chain: Vec<Arc<str>>,

    pub rcode: ResponseCode,

    pub truncated: bool,

    pub min_ttl: Option<u32>,

    pub raw_answers: Vec<Record>,

    pub negative_soa_ttl: Option<u32>,

    pub message: Message,

    /// Raw wire bytes of the upstream DNS response.
    pub raw_bytes: Bytes,
}

impl DnsResponse {
    pub fn is_nodata(&self) -> bool {
        self.rcode == ResponseCode::NoError
            && self.addresses.is_empty()
            && self.cname_chain.is_empty()
    }

    pub fn is_nxdomain(&self) -> bool {
        self.rcode == ResponseCode::NXDomain
    }

    pub fn is_server_error(&self) -> bool {
        matches!(
            self.rcode,
            ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::NotImp
        )
    }
}

pub struct ResponseParser;

impl ResponseParser {
    /// Parses DNS response from owned bytes (zero-copy for raw_bytes).
    pub fn parse_bytes(response_bytes: Bytes) -> Result<DnsResponse, DomainError> {
        let message = Message::from_vec(&response_bytes).map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to parse DNS response: {}", e))
        })?;

        let rcode = message.response_code();
        let truncated = message.truncated();

        let mut addresses = Vec::with_capacity(message.answers().len().min(8));
        let mut cname_chain: Vec<Arc<str>> = Vec::new();
        let mut min_ttl: Option<u32> = None;
        let mut raw_answers = Vec::new();

        for record in message.answers() {
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
                    let name = canonical.to_utf8();
                    debug!(cname = %name, "CNAME record found");
                    cname_chain.push(Arc::from(name.as_str()));
                }
                _ => {
                    raw_answers.push(record.clone());
                }
            }
        }

        let negative_soa_ttl = message.name_servers().iter().find_map(|r| {
            if let RData::SOA(soa) = r.data() {
                Some(soa.minimum().min(r.ttl()))
            } else {
                None
            }
        });

        debug!(
            rcode = ?rcode,
            addresses = addresses.len(),
            cname_hops = cname_chain.len(),
            truncated = truncated,
            "DNS response parsed"
        );

        Ok(DnsResponse {
            addresses,
            cname_chain,
            rcode,
            truncated,
            min_ttl,
            raw_answers,
            negative_soa_ttl,
            message,
            raw_bytes: response_bytes,
        })
    }

    pub fn parse(response_bytes: &[u8]) -> Result<DnsResponse, DomainError> {
        Self::parse_bytes(Bytes::copy_from_slice(response_bytes))
    }

    pub fn is_transport_error(error: &DomainError) -> bool {
        matches!(
            error,
            DomainError::TransportTimeout { .. }
                | DomainError::TransportConnectionRefused { .. }
                | DomainError::TransportConnectionReset { .. }
                | DomainError::TransportNoHealthyServers
                | DomainError::TransportAllServersUnreachable
                | DomainError::IoError(_)
        )
    }

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
