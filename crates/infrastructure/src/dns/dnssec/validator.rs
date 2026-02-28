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
use tracing::{debug, warn};

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
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation"
        );

        let start = std::time::Instant::now();

        let domain_arc: Arc<str> = Arc::from(domain);
        let upstream_result = self
            .pool_manager
            .query(&domain_arc, &record_type, self.timeout_ms, true)
            .await?;

        debug!(
            domain = %domain,
            server = %upstream_result.server,
            latency_ms = upstream_result.latency_ms,
            "DNS query completed"
        );

        let chain_domain = Self::extract_signer_zone(upstream_result.response.message.answers())
            .unwrap_or_else(|| domain.to_owned());

        let mut validation_status = self
            .chain_verifier
            .verify_chain(&chain_domain, record_type)
            .await?;

        if validation_status == ValidationResult::Secure {
            let all_answers: Vec<Record> = upstream_result.response.message.answers().to_vec();
            validation_status = self.verify_rrset_signatures(domain, &all_answers);
        }

        let elapsed = start.elapsed().as_millis() as u64;

        debug!(
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

    pub async fn validate_with_message(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Result<ValidatedResponse, DomainError> {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation (pre-fetched response)"
        );

        let start = std::time::Instant::now();

        let chain_domain =
            Self::extract_signer_zone(message.answers()).unwrap_or_else(|| domain.to_owned());

        let mut validation_status = self
            .chain_verifier
            .verify_chain(&chain_domain, record_type)
            .await?;

        if validation_status == ValidationResult::Secure {
            let all_answers: Vec<Record> = message.answers().to_vec();
            validation_status = self.verify_rrset_signatures(domain, &all_answers);
        }

        let elapsed = start.elapsed().as_millis() as u64;

        debug!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = elapsed,
            "DNSSEC validation completed (pre-fetched)"
        );

        Ok(ValidatedResponse {
            validation_status,
            records: vec![],
            domain: domain.to_string(),
            record_type,
            response_time_ms: elapsed,
            upstream_server: None,
        })
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

        let domain_arc: Arc<str> = Arc::from(domain);
        let result = self
            .pool_manager
            .query(&domain_arc, &RecordType::DS, self.timeout_ms, true)
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

    pub fn insert_zone_keys_for_test(
        &mut self,
        zone: &str,
        keys: Vec<crate::dns::dnssec::types::DnskeyRecord>,
    ) {
        self.chain_verifier.insert_zone_keys_for_test(zone, keys);
    }

    pub fn stats(&self) -> ValidatorStats {
        ValidatorStats {
            timeout_ms: self.timeout_ms,
            trust_anchors_count: 1,
        }
    }

    fn extract_signer_zone(answers: &[Record]) -> Option<String> {
        for record in answers {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = record.data() {
                let input = rrsig.input();
                if input.type_covered != hickory_proto::rr::RecordType::DNSKEY {
                    return Some(input.signer_name.to_string());
                }
            }
        }
        None
    }

    pub fn verify_rrset_signatures(
        &self,
        domain: &str,
        all_answers: &[Record],
    ) -> ValidationResult {
        let mut rrsigs: Vec<RrsigRecord> = Vec::new();
        let mut data_records: Vec<Record> = Vec::new();

        for record in all_answers {
            match record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    let input = rrsig.input();
                    if input.type_covered == hickory_proto::rr::RecordType::DNSKEY {
                        continue;
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
            if data_records.is_empty() {
                debug!(domain = %domain, "NODATA response — chain validation sufficient");
                return ValidationResult::Secure;
            }
            debug!(domain = %domain, "No RRSIG for RRset — returning Bogus");
            return ValidationResult::Bogus;
        }

        let crypto_verifier = SignatureVerifier;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        for rrsig in &rrsigs {
            let zone = &rrsig.signer_name;
            let Some(zone_keys) = self.chain_verifier.get_zone_keys(zone) else {
                debug!(zone = %zone, "No trusted keys for signer zone");
                continue;
            };

            let hickory_type = RecordTypeMapper::to_hickory(&rrsig.type_covered);
            let owner = data_records
                .iter()
                .find(|r| r.record_type() == hickory_type)
                .map(|r| r.name().to_string())
                .unwrap_or_else(|| {
                    if domain.ends_with('.') {
                        domain.to_string()
                    } else {
                        format!("{}.", domain)
                    }
                });

            for key in zone_keys.iter() {
                match crypto_verifier.verify_rrsig(rrsig, key, &owner, &data_records, now_secs) {
                    Ok(true) => {
                        debug!(
                            domain = %domain,
                            owner = %owner,
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
