use ferrous_dns_domain::DomainError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl DsRecord {
    pub fn parse(data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 4 {
            return Err(DomainError::InvalidDnsResponse(
                "DS record too short".into(),
            ));
        }

        let key_tag = u16::from_be_bytes([data[0], data[1]]);
        let algorithm = data[2];
        let digest_type = data[3];
        let digest = data[4..].to_vec();

        Self::validate_digest_length(digest_type, digest.len())?;

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    fn validate_digest_length(digest_type: u8, length: usize) -> Result<(), DomainError> {
        let expected = match digest_type {
            1 => 20, 
            2 => 32, 
            4 => 48, 
            _ => return Ok(()),
        };

        if length != expected {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Invalid digest length for type {}: got {}, expected {}",
                digest_type, length, expected
            )));
        }

        Ok(())
    }

    pub fn digest_type_name(&self) -> &'static str {
        match self.digest_type {
            1 => "SHA-1",
            2 => "SHA-256",
            4 => "SHA-384",
            _ => "Unknown",
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            8 => "RSA/SHA-256",
            13 => "ECDSA P-256/SHA-256",
            15 => "Ed25519",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for DsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DS(tag={}, algo={}, digest={})",
            self.key_tag,
            self.algorithm_name(),
            self.digest_type_name()
        )
    }
}
