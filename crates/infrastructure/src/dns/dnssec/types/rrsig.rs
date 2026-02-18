use ferrous_dns_domain::{DomainError, RecordType};
use std::fmt;

#[derive(Debug, Clone)]
pub struct RrsigRecord {
    pub type_covered: RecordType,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration: u32,
    pub signature_inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

impl RrsigRecord {
    pub fn parse(data: &[u8], full_data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 18 {
            return Err(DomainError::InvalidDnsResponse(
                "RRSIG record too short".into(),
            ));
        }

        let type_code = u16::from_be_bytes([data[0], data[1]]);
        let type_covered = RecordType::from_u16(type_code).ok_or_else(|| {
            DomainError::InvalidDnsResponse(format!("Unknown type: {}", type_code))
        })?;

        let algorithm = data[2];
        let labels = data[3];
        let original_ttl = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let signature_expiration = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let signature_inception = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let key_tag = u16::from_be_bytes([data[16], data[17]]);

        let (signer_name, name_len) = Self::parse_domain_name(&data[18..], full_data)?;
        let signature = data[18 + name_len..].to_vec();

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        })
    }

    fn parse_domain_name(data: &[u8], _full_data: &[u8]) -> Result<(String, usize), DomainError> {
        let mut name = String::new();
        let mut pos = 0;

        loop {
            if pos >= data.len() {
                return Err(DomainError::InvalidDnsResponse(
                    "Domain name truncated".into(),
                ));
            }

            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }

            if len > 63 {
                return Err(DomainError::InvalidDnsResponse(
                    "Invalid label length".into(),
                ));
            }

            if pos + 1 + len > data.len() {
                return Err(DomainError::InvalidDnsResponse(
                    "Label data truncated".into(),
                ));
            }

            if !name.is_empty() {
                name.push('.');
            }

            let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]);
            name.push_str(&label);
            pos += 1 + len;
        }

        Ok((name, pos))
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            8 => "RSA/SHA-256",
            13 => "ECDSA P-256/SHA-256",
            15 => "Ed25519",
            _ => "Unknown",
        }
    }

    pub fn is_expired(&self, now: u32) -> bool {
        now > self.signature_expiration
    }

    pub fn is_valid_at(&self, now: u32) -> bool {
        now >= self.signature_inception && now <= self.signature_expiration
    }
}

impl fmt::Display for RrsigRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RRSIG({:?}, algo={}, tag={}, signer={})",
            self.type_covered,
            self.algorithm_name(),
            self.key_tag,
            self.signer_name
        )
    }
}
