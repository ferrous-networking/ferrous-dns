use super::types::{DnskeyRecord, DsRecord, RrsigRecord};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use ferrous_dns_domain::DomainError;
use hickory_proto::dnssec::rdata::sig::SigInput;
use hickory_proto::dnssec::tbs::TBS;
use hickory_proto::dnssec::Algorithm;
use hickory_proto::rr::{DNSClass, Name, Record, SerialNumber};
use ring::signature;
use sha1::Digest as Sha1Digest;
use sha2::{Sha256, Sha384};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn verify_rrsig(
        &self,
        rrsig: &RrsigRecord,
        dnskey: &DnskeyRecord,
        domain: &str,
        records: &[Record],
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

        let fqdn = if domain.ends_with('.') {
            domain.to_owned()
        } else {
            format!("{}.", domain)
        };
        let name =
            Name::from_str(&fqdn).map_err(|e| DomainError::InvalidDnsResponse(e.to_string()))?;
        let signer_name = Name::from_str(&rrsig.signer_name)
            .map_err(|e| DomainError::InvalidDnsResponse(e.to_string()))?;
        let hickory_type = RecordTypeMapper::to_hickory(&rrsig.type_covered);

        let sig_input = SigInput {
            type_covered: hickory_type,
            algorithm: Algorithm::from_u8(rrsig.algorithm),
            num_labels: rrsig.labels,
            original_ttl: rrsig.original_ttl,
            sig_expiration: SerialNumber::from(rrsig.signature_expiration),
            sig_inception: SerialNumber::from(rrsig.signature_inception),
            key_tag: rrsig.key_tag,
            signer_name,
        };

        let tbs = TBS::from_input(&name, DNSClass::IN, &sig_input, records.iter())
            .map_err(|e| DomainError::InvalidDnsResponse(e.to_string()))?;
        let data_to_verify = tbs.as_ref();

        match rrsig.algorithm {
            5 | 7 => self.verify_rsa_sha1(data_to_verify, &rrsig.signature, dnskey),
            8 => self.verify_rsa_sha256(data_to_verify, &rrsig.signature, dnskey),
            10 => self.verify_rsa_sha512(data_to_verify, &rrsig.signature, dnskey),
            13 => self.verify_ecdsa_p256(data_to_verify, &rrsig.signature, dnskey),
            14 => self.verify_ecdsa_p384(data_to_verify, &rrsig.signature, dnskey),
            15 => self.verify_ed25519(data_to_verify, &rrsig.signature, dnskey),
            16 => Err(DomainError::InvalidDnsResponse(
                "Ed448 (algorithm 16) is not supported by this build".into(),
            )),
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
            1 => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(&dnskey_data);
                hasher.finalize().to_vec()
            }
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

    fn verify_rsa_sha1(
        &self,
        data: &[u8],
        sig: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        let (exponent, modulus) = self.parse_rsa_key(&dnskey.public_key)?;
        let public_key = signature::RsaPublicKeyComponents {
            n: &modulus,
            e: &exponent,
        };
        match public_key.verify(
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            data,
            sig,
        ) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_rsa_sha256(
        &self,
        data: &[u8],
        sig: &[u8],
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

        match public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, data, sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_rsa_sha512(
        &self,
        data: &[u8],
        sig: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        let (exponent, modulus) = self.parse_rsa_key(&dnskey.public_key)?;
        let public_key = signature::RsaPublicKeyComponents {
            n: &modulus,
            e: &exponent,
        };
        match public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA512, data, sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ecdsa_p256(
        &self,
        data: &[u8],
        sig: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        if dnskey.public_key.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-256 public key length".into(),
            ));
        }

        if sig.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-256 signature length".into(),
            ));
        }

        let mut pk = Vec::with_capacity(65);
        pk.push(0x04);
        pk.extend_from_slice(&dnskey.public_key);

        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pk);

        match public_key.verify(data, sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ecdsa_p384(
        &self,
        data: &[u8],
        sig: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        if dnskey.public_key.len() != 96 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-384 public key length".into(),
            ));
        }

        if sig.len() != 96 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-384 signature length".into(),
            ));
        }

        let mut pk = Vec::with_capacity(97);
        pk.push(0x04);
        pk.extend_from_slice(&dnskey.public_key);

        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &pk);

        match public_key.verify(data, sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ed25519(
        &self,
        data: &[u8],
        sig: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        if dnskey.public_key.len() != 32 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid Ed25519 public key length".into(),
            ));
        }

        if sig.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid Ed25519 signature length".into(),
            ));
        }

        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key);

        match public_key.verify(data, sig) {
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
