use super::cache::DnssecCache;
use super::crypto::SignatureVerifier;
use super::trust_anchor::TrustAnchorStore;
use super::types::RrsigRecord;
use super::validation::denial::{
    prove_denial, prove_wildcard_expansion, VerifiedNsec, VerifiedNsec3,
};
use super::validation::{ChainVerifier, ValidationResult};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{Name, RData, Record};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, warn};

/// Current UNIX time in seconds, clamped to `u32` (RRSIG timestamp domain).
fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

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

        let validation_status = self
            .validate_message(domain, record_type, &upstream_result.response.message)
            .await?;

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

        let validation_status = self.validate_message(domain, record_type, message).await?;

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

    /// Runs full validation over an already-fetched message: positive answers go
    /// through RRset signature + wildcard-expansion checks; empty answers
    /// (NXDOMAIN / NODATA) go through authenticated denial of existence.
    async fn validate_message(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Result<ValidationResult, DomainError> {
        if message.answers().is_empty() {
            return self.validate_negative(domain, record_type, message).await;
        }

        let chain_domain =
            Self::extract_signer_zone(message.answers()).unwrap_or_else(|| domain.to_owned());
        let mut status = self
            .chain_verifier
            .verify_chain(&chain_domain, record_type)
            .await?;

        if status == ValidationResult::Secure {
            let all_answers: Vec<Record> = message.answers().to_vec();
            status = self.verify_rrset_signatures(domain, &all_answers);
            if status == ValidationResult::Secure {
                status = self.verify_wildcard_proof(domain, &all_answers, message.name_servers());
            }
        }
        Ok(status)
    }

    /// Validates a negative response. Anchors the chain at the authority's signer
    /// zone, then proves the denial from the NSEC/NSEC3 records.
    async fn validate_negative(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Result<ValidationResult, DomainError> {
        let Some(zone) = Self::extract_signer_zone(message.name_servers()) else {
            // No signed authority section: unsigned negative, serve without AD.
            return Ok(ValidationResult::Insecure);
        };
        let chain_status = self.chain_verifier.verify_chain(&zone, record_type).await?;
        if chain_status != ValidationResult::Secure {
            return Ok(chain_status);
        }
        Ok(self.validate_denial(
            domain,
            record_type,
            message.response_code(),
            &zone,
            message.name_servers(),
        ))
    }

    /// Builds an FQDN (trailing dot) hickory [`Name`], or `None` on parse error.
    fn to_name(domain: &str) -> Option<Name> {
        let fqdn = if domain.ends_with('.') {
            domain.to_owned()
        } else {
            format!("{domain}.")
        };
        Name::from_str(&fqdn).ok()
    }

    /// True when `record` (a single-record NSEC/NSEC3 RRset) is covered by a
    /// valid RRSIG in `authority`, signed by a key already established in the
    /// chain of trust.
    fn rrset_is_authentic(
        &self,
        record: &Record,
        authority: &[Record],
        crypto: &SignatureVerifier,
        now_secs: u32,
    ) -> bool {
        let owner = record.name();
        let rtype = record.record_type();
        let data_records = [record.clone()];
        let mut outcome = "no-rrsig";

        for sig in authority {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = sig.data() else {
                continue;
            };
            if sig.name() != owner {
                continue;
            }
            let input = rrsig.input();
            if input.type_covered != rtype {
                continue;
            }
            let Some(type_covered) = RecordTypeMapper::from_hickory(input.type_covered) else {
                continue;
            };
            let rr = RrsigRecord {
                type_covered,
                algorithm: u8::from(input.algorithm),
                labels: input.num_labels,
                original_ttl: input.original_ttl,
                signature_expiration: input.sig_expiration.get(),
                signature_inception: input.sig_inception.get(),
                key_tag: input.key_tag,
                signer_name: input.signer_name.to_string(),
                signature: rrsig.sig().to_vec(),
            };
            let Some(keys) = self.chain_verifier.get_zone_keys(&rr.signer_name) else {
                outcome = "no-keys";
                continue;
            };
            for key in keys.iter() {
                match crypto.verify_rrsig_with_name(&rr, key, owner, &data_records, now_secs) {
                    Ok(true) => return true,
                    Ok(false) => outcome = "sig-false",
                    Err(_) => outcome = "sig-err",
                }
            }
        }
        debug!(owner = %owner, ?rtype, outcome, "denial: rrset not authentic");
        false
    }

    /// Collects the cryptographically-authentic NSEC3 and NSEC records from an
    /// authority section.
    fn collect_verified_denial<'a>(
        &self,
        authority: &'a [Record],
        crypto: &SignatureVerifier,
        now_secs: u32,
    ) -> (Vec<VerifiedNsec3<'a>>, Vec<VerifiedNsec<'a>>) {
        let mut nsec3s: Vec<VerifiedNsec3<'a>> = Vec::new();
        let mut nsecs: Vec<VerifiedNsec<'a>> = Vec::new();

        for record in authority {
            match record.data() {
                RData::DNSSEC(DNSSECRData::NSEC3(nsec3))
                    if self.rrset_is_authentic(record, authority, crypto, now_secs) =>
                {
                    if let Some(label) = record
                        .name()
                        .iter()
                        .next()
                        .and_then(|first| Label::from_raw_bytes(first).ok())
                    {
                        nsec3s.push(VerifiedNsec3 {
                            owner_label: label,
                            data: nsec3,
                        });
                    }
                }
                RData::DNSSEC(DNSSECRData::NSEC(nsec))
                    if self.rrset_is_authentic(record, authority, crypto, now_secs) =>
                {
                    nsecs.push(VerifiedNsec {
                        owner: record.name(),
                        data: nsec,
                    });
                }
                _ => {}
            }
        }
        (nsec3s, nsecs)
    }

    /// Validates an authenticated denial of existence (NXDOMAIN / NODATA) using
    /// the NSEC/NSEC3 records of the authority section. `soa_zone` is the signed
    /// zone apex already established in the chain.
    fn validate_denial(
        &self,
        qname: &str,
        qtype: RecordType,
        rcode: ResponseCode,
        soa_zone: &str,
        authority: &[Record],
    ) -> ValidationResult {
        let now = now_secs();
        let crypto = SignatureVerifier;
        let (nsec3s, nsecs) = self.collect_verified_denial(authority, &crypto, now);

        if nsec3s.is_empty() && nsecs.is_empty() {
            // Signed zone but no authenticated denial records: stripped / forged.
            return ValidationResult::Bogus;
        }

        let (Some(qname_name), Some(soa_name)) = (Self::to_name(qname), Self::to_name(soa_zone))
        else {
            return ValidationResult::Insecure;
        };
        let qtype_hickory = RecordTypeMapper::to_hickory(&qtype);

        let result = prove_denial(
            &qname_name,
            qtype_hickory,
            rcode,
            &soa_name,
            &nsec3s,
            &nsecs,
        );
        debug!(
            domain = %qname,
            zone = %soa_zone,
            ?rcode,
            nsec3 = nsec3s.len(),
            nsec = nsecs.len(),
            status = %result.as_str(),
            "denial of existence validated"
        );
        result
    }

    /// Verifies the wildcard-expansion proof for a *positive* answer
    /// (RFC 4035 §5.3.4). Returns `Secure` when the answer is not wildcard-
    /// expanded (nothing to prove) or the proof is valid; `Bogus` when the
    /// claimed expansion lacks a denial of the exact name.
    fn verify_wildcard_proof(
        &self,
        qname: &str,
        answers: &[Record],
        authority: &[Record],
    ) -> ValidationResult {
        let mut wildcard_labels: Option<u8> = None;
        for record in answers {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = record.data() {
                let input = rrsig.input();
                if input.type_covered == hickory_proto::rr::RecordType::DNSKEY {
                    continue;
                }
                if input.num_labels < record.name().num_labels() {
                    wildcard_labels = Some(input.num_labels);
                    break;
                }
            }
        }
        let Some(wildcard_labels) = wildcard_labels else {
            return ValidationResult::Secure;
        };

        let now = now_secs();
        let crypto = SignatureVerifier;
        let (nsec3s, nsecs) = self.collect_verified_denial(authority, &crypto, now);
        let Some(qname_name) = Self::to_name(qname) else {
            return ValidationResult::Insecure;
        };
        prove_wildcard_expansion(&qname_name, wildcard_labels, &nsec3s, &nsecs)
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
                // Empty answers are routed to authenticated denial of existence
                // before reaching here; treat any stray empty RRset as undecided
                // rather than blindly authentic.
                debug!(domain = %domain, "No answer RRset to verify");
                return ValidationResult::Indeterminate;
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
