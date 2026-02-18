use ferrous_dns_domain::DomainError;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};
use std::net::IpAddr;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub addresses: Vec<IpAddr>,

    pub cname: Option<String>,

    pub rcode: ResponseCode,

    pub truncated: bool,

    pub min_ttl: Option<u32>,

    pub raw_answers: Vec<Record>,

    pub authority_records: Vec<Record>,

    pub message: Message,
}

impl DnsResponse {
    pub fn is_nodata(&self) -> bool {
        self.rcode == ResponseCode::NoError && self.addresses.is_empty() && self.cname.is_none()
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
    pub fn parse(response_bytes: &[u8]) -> Result<DnsResponse, DomainError> {
        let message = Message::from_vec(response_bytes).map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to parse DNS response: {}", e))
        })?;

        let rcode = message.response_code();
        let truncated = message.truncated();

        let mut addresses = Vec::new();
        let mut cname: Option<String> = None;
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
                    if cname.is_none() {
                        cname = Some(canonical.to_utf8());
                        debug!(cname = %canonical.to_utf8(), "CNAME record found");
                    }
                }
                _ => {
                    raw_answers.push(record.clone());
                }
            }
        }

        let authority_records: Vec<Record> = message.name_servers().to_vec();

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
