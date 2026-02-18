use super::cache::DnssecCache;
use super::crypto::SignatureVerifier;
use super::trust_anchor::TrustAnchorStore;
use super::types::RrsigRecord;
use super::validation::{ChainVerifier, ValidationResult};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::{RData, Record};
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct ValidatedResponse {
    pub validation_status: ValidationResult,

    pub records: Vec<String>,

    pub domain: String,

    pub record_type: RecordType,

    pub response_time_ms: u64,

    pub upstream_server: Option<String>,
}

impl ValidatedResponse {
    pub fn new(
        validation_status: ValidationResult,
        records: Vec<String>,
        domain: String,
        record_type: RecordType,
    ) -> Self {
        Self {
            validation_status,
            records,
            domain,
            record_type,
            response_time_ms: 0,
            upstream_server: None,
        }
    }

    pub fn is_secure(&self) -> bool {
        matches!(self.validation_status, ValidationResult::Secure)
    }

    pub fn is_insecure(&self) -> bool {
        matches!(self.validation_status, ValidationResult::Insecure)
    }

    pub fn is_bogus(&self) -> bool {
        matches!(self.validation_status, ValidationResult::Bogus)
    }
}

pub struct DnssecValidator {
    pool_manager: Arc<PoolManager>,

    chain_verifier: ChainVerifier,

    timeout_ms: u64,
}

impl DnssecValidator {
    pub fn new(pool_manager: Arc<PoolManager>) -> Self {
        let trust_store = TrustAnchorStore::new();
        let dnssec_cache = Arc::new(DnssecCache::new());
        let chain_verifier = ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms: 5000,
        }
    }

    pub fn with_cache(pool_manager: Arc<PoolManager>, dnssec_cache: Arc<DnssecCache>) -> Self {
        let trust_store = TrustAnchorStore::new();
        let chain_verifier = ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms: 5000,
        }
    }

    pub fn with_trust_store(pool_manager: Arc<PoolManager>, trust_store: TrustAnchorStore) -> Self {
        let dnssec_cache = Arc::new(DnssecCache::new());
        let chain_verifier = ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms: 5000,
        }
    }

    pub fn with_trust_store_and_cache(
        pool_manager: Arc<PoolManager>,
        trust_store: TrustAnchorStore,
        dnssec_cache: Arc<DnssecCache>,
    ) -> Self {
        let chain_verifier = ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub async fn validate_query(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidatedResponse, DomainError> {
        info!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation"
        );

        let start = std::time::Instant::now();

        let upstream_result = self
            .pool_manager
            .query(domain, &record_type, self.timeout_ms)
            .await?;

        debug!(
            domain = %domain,
            server = %upstream_result.server,
            latency_ms = upstream_result.latency_ms,
            "DNS query completed"
        );

        let mut validation_status = self
            .chain_verifier
            .verify_chain(domain, record_type)
            .await?;

        // Phase 2: verify RRSIG over the final RRset using ZSKs from the validated chain.
        if validation_status == ValidationResult::Secure {
            let all_answers: Vec<Record> = upstream_result.response.message.answers().to_vec();
            validation_status = self.verify_rrset_signatures(domain, &all_answers);
        }

        let elapsed = start.elapsed().as_millis() as u64;

        info!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = elapsed,
            "DNSSEC validation completed"
        );

        let response = ValidatedResponse {
            validation_status,
            records: upstream_result
                .response
                .addresses
                .iter()
                .map(|ip| ip.to_string())
                .collect(),
            domain: domain.to_string(),
            record_type,
            response_time_ms: elapsed,
            upstream_server: Some(upstream_result.server.to_string()),
        };

        Ok(response)
    }

    pub async fn validate_simple(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidationResult, DomainError> {
        let response = self.validate_query(domain, record_type).await?;
        Ok(response.validation_status)
    }

    pub async fn has_dnssec(&self, domain: &str) -> Result<bool, DomainError> {
        debug!(domain = %domain, "Checking DNSSEC availability");

        let result = self
            .pool_manager
            .query(domain, &RecordType::DS, self.timeout_ms)
            .await;

        match result {
            Ok(_upstream_result) => {
                debug!(domain = %domain, "DNSSEC check: DS query successful");
                Ok(true)
            }
            Err(_) => {
                debug!(domain = %domain, "DNSSEC check: No DS records");
                Ok(false)
            }
        }
    }

    pub fn stats(&self) -> ValidatorStats {
        ValidatorStats {
            timeout_ms: self.timeout_ms,
            trust_anchors_count: 1,
        }
    }

    fn verify_rrset_signatures(&self, domain: &str, all_answers: &[Record]) -> ValidationResult {
        let mut rrsigs: Vec<RrsigRecord> = Vec::new();
        let mut data_records: Vec<Record> = Vec::new();

        for record in all_answers {
            match record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    let input = rrsig.input();
                    if input.type_covered == hickory_proto::rr::RecordType::DNSKEY {
                        continue; // already verified in chain
                    }
                    let Some(type_covered) = RecordTypeMapper::from_hickory(input.type_covered)
                    else {
                        continue;
                    };
                    rrsigs.push(RrsigRecord {
                        type_covered,
                        algorithm: u8::from(input.algorithm),
                        labels: input.num_labels,
                        original_ttl: input.original_ttl,
                        signature_expiration: input.sig_expiration.get(),
                        signature_inception: input.sig_inception.get(),
                        key_tag: input.key_tag,
                        signer_name: input.signer_name.to_string(),
                        signature: rrsig.sig().to_vec(),
                    });
                }
                _ => data_records.push(record.clone()),
            }
        }

        if rrsigs.is_empty() {
            debug!(domain = %domain, "No RRSIG for RRset — returning Bogus");
            return ValidationResult::Bogus;
        }

        let crypto_verifier = SignatureVerifier;

        for rrsig in &rrsigs {
            let zone = &rrsig.signer_name;
            let Some(zone_keys) = self.chain_verifier.get_zone_keys(zone) else {
                debug!(zone = %zone, "No trusted keys for signer zone");
                continue;
            };
            for key in zone_keys {
                match crypto_verifier.verify_rrsig(rrsig, key, domain, &data_records) {
                    Ok(true) => {
                        debug!(
                            domain = %domain,
                            key_tag = key.calculate_key_tag(),
                            "RRset RRSIG verified"
                        );
                        return ValidationResult::Secure;
                    }
                    Ok(false) => {}
                    Err(e) => warn!(error = %e, "RRset RRSIG error"),
                }
            }
        }

        warn!(domain = %domain, "RRset RRSIG verification failed");
        ValidationResult::Bogus
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorStats {
    pub timeout_ms: u64,
    pub trust_anchors_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::dnssec::trust_anchor::TrustAnchorStore;
    use crate::dns::events::QueryEventEmitter;
    use crate::dns::load_balancer::PoolManager;
    use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::Arc;

    fn make_validator() -> DnssecValidator {
        let pool = UpstreamPool {
            name: "test".into(),
            strategy: UpstreamStrategy::Parallel,
            priority: 1,
            servers: vec!["udp://127.0.0.1:5353".into()],
            weight: None,
        };
        let pm = Arc::new(
            PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled()).unwrap(),
        );
        DnssecValidator::with_trust_store(pm, TrustAnchorStore::empty())
    }

    fn make_a_record(name: &str, ip: Ipv4Addr) -> Record {
        let name = Name::from_str(name).unwrap();
        Record::from_rdata(name, 300, RData::A(A(ip)))
    }

    // -------------------------------------------------------------------------
    // verify_rrset_signatures — negative paths
    // -------------------------------------------------------------------------

    #[test]
    fn test_verify_rrset_empty_records_returns_bogus() {
        let validator = make_validator();
        assert_eq!(
            validator.verify_rrset_signatures("example.com.", &[]),
            ValidationResult::Bogus
        );
    }

    #[test]
    fn test_verify_rrset_a_records_only_no_rrsig_returns_bogus() {
        let validator = make_validator();
        let a = make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(
            validator.verify_rrset_signatures("example.com.", &[a]),
            ValidationResult::Bogus
        );
    }

    #[test]
    fn test_verify_rrset_multiple_a_records_no_rrsig_returns_bogus() {
        let validator = make_validator();
        let records: Vec<Record> = [
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(9, 10, 11, 12),
        ]
        .iter()
        .map(|ip| make_a_record("example.com.", *ip))
        .collect();
        assert_eq!(
            validator.verify_rrset_signatures("example.com.", &records),
            ValidationResult::Bogus
        );
    }

    // -------------------------------------------------------------------------
    // verify_rrset_signatures — RRSIG present but no trusted zone keys
    // -------------------------------------------------------------------------

    #[test]
    fn test_verify_rrset_rrsig_present_no_zone_keys_returns_bogus() {
        use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
        use hickory_proto::dnssec::{
            crypto::Ed25519SigningKey, Algorithm, PublicKey, PublicKeyBuf, SigSigner, SigningKey,
        };
        use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
        use time::{Duration as TD, OffsetDateTime};

        let validator = make_validator(); // no zone keys in chain_verifier

        // Generate a real signing key so we can build a valid RRSIG record.
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
        let pub_key_buf = signing_key.to_public_key().unwrap();
        let pub_bytes = pub_key_buf.public_bytes().to_vec();

        let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
        let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
        let signer_name = Name::from_str("example.com.").unwrap();
        let sig_duration = std::time::Duration::from_secs(7200);
        let signer = SigSigner::dnssec(
            h_dnskey,
            Box::new(signing_key),
            signer_name.clone(),
            sig_duration,
        );

        let record_name = Name::from_str("example.com.").unwrap();
        let a_record = make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4));
        let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
        rrset.insert(a_record.clone(), 0);

        let inception = OffsetDateTime::now_utc() - TD::minutes(5);
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
        let rrsig_record =
            Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

        // RRSIG is present but the zone "example.com." has no trusted keys in the chain.
        let answers = vec![a_record, rrsig_record];
        assert_eq!(
            validator.verify_rrset_signatures("example.com.", &answers),
            ValidationResult::Bogus
        );
    }

    // -------------------------------------------------------------------------
    // verify_rrset_signatures — valid RRSIG with matching zone key → Secure
    // -------------------------------------------------------------------------

    #[test]
    fn test_verify_rrset_valid_ed25519_rrsig_returns_secure() {
        use crate::dns::dnssec::types::DnskeyRecord;
        use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
        use hickory_proto::dnssec::{
            crypto::Ed25519SigningKey, Algorithm, PublicKey, PublicKeyBuf, SigSigner, SigningKey,
        };
        use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
        use time::{Duration as TD, OffsetDateTime};

        let mut validator = make_validator();

        // Generate Ed25519 ZSK.
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
        let pub_key_buf = signing_key.to_public_key().unwrap();
        let pub_bytes = pub_key_buf.public_bytes().to_vec();

        // Build our DnskeyRecord (ZSK, flags=256, algo=15) with the same public key.
        let our_dnskey = DnskeyRecord {
            flags: 256,
            protocol: 3,
            algorithm: 15,
            public_key: pub_bytes.clone(),
        };

        // Build hickory DNSKEY that matches our DnskeyRecord exactly so key_tags agree.
        let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
        let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
        let signer_name = Name::from_str("example.com.").unwrap();
        let sig_duration = std::time::Duration::from_secs(7200);
        let signer = SigSigner::dnssec(
            h_dnskey,
            Box::new(signing_key),
            signer_name.clone(),
            sig_duration,
        );

        // Build A record + RecordSet.
        let record_name = Name::from_str("example.com.").unwrap();
        let a_record = make_a_record("example.com.", Ipv4Addr::new(93, 184, 216, 34));
        let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
        rrset.insert(a_record.clone(), 0);

        // Sign the RRset.
        let inception = OffsetDateTime::now_utc() - TD::minutes(5);
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
        let rrsig_record =
            Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

        // Register the ZSK as a trusted key for the zone.
        validator
            .chain_verifier
            .insert_zone_keys_for_test("example.com.", vec![our_dnskey]);

        // Should successfully verify the RRSIG and return Secure.
        let answers = vec![a_record, rrsig_record];
        assert_eq!(
            validator.verify_rrset_signatures("example.com.", &answers),
            ValidationResult::Secure
        );
    }

    #[test]
    fn test_verify_rrset_wrong_zone_key_returns_bogus() {
        use crate::dns::dnssec::types::DnskeyRecord;
        use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
        use hickory_proto::dnssec::{
            crypto::Ed25519SigningKey, Algorithm, PublicKeyBuf, SigSigner, SigningKey,
        };
        use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
        use time::{Duration as TD, OffsetDateTime};

        let mut validator = make_validator();

        // Signing key used to create RRSIG.
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
        let pub_key_buf = signing_key.to_public_key().unwrap();
        let pub_bytes: Vec<u8> = {
            use hickory_proto::dnssec::PublicKey;
            pub_key_buf.public_bytes().to_vec()
        };

        let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
        let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
        let signer_name = Name::from_str("example.com.").unwrap();
        let sig_duration = std::time::Duration::from_secs(7200);
        let signer = SigSigner::dnssec(
            h_dnskey,
            Box::new(signing_key),
            signer_name.clone(),
            sig_duration,
        );

        let record_name = Name::from_str("example.com.").unwrap();
        let a_record = make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4));
        let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
        rrset.insert(a_record.clone(), 0);

        let inception = OffsetDateTime::now_utc() - TD::minutes(5);
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
        let rrsig_record =
            Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

        // Register a DIFFERENT key (wrong key — can't verify the RRSIG).
        let wrong_key = DnskeyRecord {
            flags: 256,
            protocol: 3,
            algorithm: 15,
            public_key: vec![0u8; 32], // all-zero key, not the real signing key
        };
        validator
            .chain_verifier
            .insert_zone_keys_for_test("example.com.", vec![wrong_key]);

        let answers = vec![a_record, rrsig_record];
        assert_eq!(
            validator.verify_rrset_signatures("example.com.", &answers),
            ValidationResult::Bogus
        );
    }
}
