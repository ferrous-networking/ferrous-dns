use ferrous_dns_domain::DomainError;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnskeyRecord {
    pub fn parse(data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 4 {
            return Err(DomainError::InvalidDnsResponse(
                "DNSKEY record too short".into(),
            ));
        }

        let flags = u16::from_be_bytes([data[0], data[1]]);
        let protocol = data[2];
        let algorithm = data[3];
        let public_key = data[4..].to_vec();

        if protocol != 3 {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Invalid DNSKEY protocol: {} (expected 3)",
                protocol
            )));
        }

        if flags & 0x0100 == 0 {
            return Err(DomainError::InvalidDnsResponse(
                "DNSKEY Zone Key flag not set".into(),
            ));
        }

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    pub fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    pub fn is_zsk(&self) -> bool {
        !self.is_ksk()
    }

    pub fn calculate_key_tag(&self) -> u16 {
        let mut wire = Vec::with_capacity(4 + self.public_key.len());
        wire.extend_from_slice(&self.flags.to_be_bytes());
        wire.push(self.protocol);
        wire.push(self.algorithm);
        wire.extend_from_slice(&self.public_key);

        let mut accumulator: u32 = 0;

        for chunk in wire.chunks(2) {
            if chunk.len() == 2 {
                accumulator += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            } else {
                accumulator += u32::from(chunk[0]) << 8;
            }
        }

        accumulator += accumulator >> 16;
        (accumulator & 0xFFFF) as u16
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

impl fmt::Display for DnskeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNSKEY(flags={}, algo={}, tag={}, {})",
            self.flags,
            self.algorithm_name(),
            self.calculate_key_tag(),
            if self.is_ksk() { "KSK" } else { "ZSK" }
        )
    }
}
