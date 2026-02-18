use super::types::{DnskeyRecord, DsRecord, RrsigRecord};
use ferrous_dns_domain::DomainError;
use ring::signature;
use sha2::{Digest, Sha256, Sha384};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn verify_rrsig(
        &self,
        rrsig: &RrsigRecord,
        dnskey: &DnskeyRecord,
        _rrset: &[String],
    ) -> Result<bool, DomainError> {
        if !self.is_time_valid(rrsig) {
            return Ok(false);
        }

        let key_tag = dnskey.calculate_key_tag();
        if key_tag != rrsig.key_tag {
            return Ok(false);
        }

        if dnskey.algorithm != rrsig.algorithm {
            return Ok(false);
        }

        let data_to_verify = self.build_rrsig_data(rrsig)?;

        match rrsig.algorithm {
            8 => self.verify_rsa_sha256(&data_to_verify, &rrsig.signature, dnskey),
            13 => self.verify_ecdsa_p256(&data_to_verify, &rrsig.signature, dnskey),
            15 => self.verify_ed25519(&data_to_verify, &rrsig.signature, dnskey),
            _ => Err(DomainError::InvalidDnsResponse(format!(
                "Unsupported DNSSEC algorithm: {}",
                rrsig.algorithm
            ))),
        }
    }

    pub fn verify_ds(
        &self,
        ds: &DsRecord,
        dnskey: &DnskeyRecord,
        owner_name: &str,
    ) -> Result<bool, DomainError> {
        let key_tag = dnskey.calculate_key_tag();
        if key_tag != ds.key_tag {
            return Ok(false);
        }

        if dnskey.algorithm != ds.algorithm {
            return Ok(false);
        }

        let dnskey_data = self.build_dnskey_data(dnskey, owner_name)?;

        let computed_digest = match ds.digest_type {
            2 => {
                let mut hasher = Sha256::new();
                hasher.update(&dnskey_data);
                hasher.finalize().to_vec()
            }
            4 => {
                let mut hasher = Sha384::new();
                hasher.update(&dnskey_data);
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(DomainError::InvalidDnsResponse(format!(
                    "Unsupported DS digest type: {}",
                    ds.digest_type
                )))
            }
        };

        Ok(computed_digest == ds.digest)
    }

    fn verify_rsa_sha256(
        &self,
        data: &[u8],
        signature: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        if dnskey.public_key.len() < 3 {
            return Err(DomainError::InvalidDnsResponse(
                "RSA public key too short".into(),
            ));
        }

        let (exponent, modulus) = self.parse_rsa_key(&dnskey.public_key)?;

        let public_key = signature::RsaPublicKeyComponents {
            n: &modulus,
            e: &exponent,
        };

        match public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ecdsa_p256(
        &self,
        data: &[u8],
        signature: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        if dnskey.public_key.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-256 public key length".into(),
            ));
        }

        if signature.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-256 signature length".into(),
            ));
        }

        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &dnskey.public_key,
        );

        match public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ed25519(
        &self,
        data: &[u8],
        signature: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        if dnskey.public_key.len() != 32 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid Ed25519 public key length".into(),
            ));
        }

        if signature.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid Ed25519 signature length".into(),
            ));
        }

        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key);

        match public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn parse_rsa_key(&self, key_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DomainError> {
        if key_data.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "Empty RSA public key".into(),
            ));
        }

        let first_byte = key_data[0];

        let (exp_len, exp_start) = if first_byte == 0 {
            if key_data.len() < 3 {
                return Err(DomainError::InvalidDnsResponse(
                    "RSA key too short for long form".into(),
                ));
            }
            let exp_len = u16::from_be_bytes([key_data[1], key_data[2]]) as usize;
            (exp_len, 3)
        } else {
            (first_byte as usize, 1)
        };

        let exp_end = exp_start + exp_len;
        if exp_end > key_data.len() {
            return Err(DomainError::InvalidDnsResponse(
                "RSA exponent extends beyond key data".into(),
            ));
        }

        let exponent = key_data[exp_start..exp_end].to_vec();
        let modulus = key_data[exp_end..].to_vec();

        if modulus.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "RSA modulus is empty".into(),
            ));
        }

        Ok((exponent, modulus))
    }

    fn build_rrsig_data(&self, rrsig: &RrsigRecord) -> Result<Vec<u8>, DomainError> {
        let mut data = Vec::new();

        data.extend_from_slice(&rrsig.type_covered.to_u16().to_be_bytes());
        data.push(rrsig.algorithm);
        data.push(rrsig.labels);
        data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        data.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
        data.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
        data.extend_from_slice(&rrsig.key_tag.to_be_bytes());

        let signer_wire = self.name_to_wire(&rrsig.signer_name)?;
        data.extend_from_slice(&signer_wire);

        Ok(data)
    }

    fn build_dnskey_data(
        &self,
        dnskey: &DnskeyRecord,
        owner_name: &str,
    ) -> Result<Vec<u8>, DomainError> {
        let mut data = Vec::new();

        let name_wire = self.name_to_wire(owner_name)?;
        data.extend_from_slice(&name_wire);

        data.extend_from_slice(&dnskey.flags.to_be_bytes());
        data.push(dnskey.protocol);
        data.push(dnskey.algorithm);
        data.extend_from_slice(&dnskey.public_key);

        Ok(data)
    }

    fn name_to_wire(&self, name: &str) -> Result<Vec<u8>, DomainError> {
        let mut wire = Vec::new();

        let name = name.trim_end_matches('.');

        if name.is_empty() || name == "." {
            wire.push(0);
            return Ok(wire);
        }

        for label in name.split('.') {
            if label.is_empty() {
                return Err(DomainError::InvalidDnsResponse("Empty DNS label".into()));
            }

            if label.len() > 63 {
                return Err(DomainError::InvalidDnsResponse("DNS label too long".into()));
            }

            wire.push(label.len() as u8);

            wire.extend_from_slice(label.to_lowercase().as_bytes());
        }

        wire.push(0);

        Ok(wire)
    }

    fn is_time_valid(&self, rrsig: &RrsigRecord) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        now >= rrsig.signature_inception && now <= rrsig.signature_expiration
    }
}
