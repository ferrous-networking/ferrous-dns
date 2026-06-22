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

    /// Distinct signer zones across all non-DNSKEY RRSIGs in `answers`, in order
    /// of first appearance. A cross-zone CNAME chain is signed by more than one
    /// zone, each of which must be anchored before its RRset can be trusted.
    fn extract_signer_zones(answers: &[Record]) -> Vec<String> {
        let mut zones: Vec<String> = Vec::new();
        for record in answers {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = record.data() {
                let input = rrsig.input();
                if input.type_covered == hickory_proto::rr::RecordType::DNSKEY {
                    continue;
                }
                let signer = input.signer_name.to_string();
                if !zones.contains(&signer) {
                    zones.push(signer);
                }
            }
        }
        zones
    }

    /// Combines per-zone chain-validation outcomes for a multi-signer answer.
    /// The answer is only `Secure` when every signer zone validates; otherwise
    /// the most severe outcome wins (Bogus > Indeterminate > Insecure).
    fn combine_chain_status(a: ValidationResult, b: ValidationResult) -> ValidationResult {
        match (a, b) {
            (ValidationResult::Bogus, _) | (_, ValidationResult::Bogus) => ValidationResult::Bogus,
            (ValidationResult::Indeterminate, _) | (_, ValidationResult::Indeterminate) => {
                ValidationResult::Indeterminate
            }
            (ValidationResult::Insecure, _) | (_, ValidationResult::Insecure) => {
                ValidationResult::Insecure
            }
            _ => ValidationResult::Secure,
        }
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

        // Establish the chain of trust for *every* signer zone present in the
        // answer (a cross-zone CNAME chain carries more than one), so each answer
        // RRset can later be checked against the keys of its own signer zone. If
        // the answer is unsigned there are no signer zones; fall back to the
        // queried name so an insecure delegation is still detected.
        let mut signer_zones = Self::extract_signer_zones(message.answers());
        if signer_zones.is_empty() {
            signer_zones.push(domain.to_owned());
        }
        let mut status = ValidationResult::Secure;
        for zone in &signer_zones {
            let zone_status = self.chain_verifier.verify_chain(zone, record_type).await?;
            status = Self::combine_chain_status(status, zone_status);
        }

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

    /// True when the `rrset` (every record sharing `owner` + `rtype`) is covered
    /// by a valid RRSIG in `sigs`, signed by a key already established in the
    /// chain of trust. Used both for single-record NSEC/NSEC3 authority RRsets
    /// and for multi-record positive-answer RRsets.
    fn rrset_is_authentic(
        &self,
        owner: &Name,
        rtype: hickory_proto::rr::RecordType,
        rrset: &[Record],
        sigs: &[Record],
        crypto: &SignatureVerifier,
        now_secs: u32,
    ) -> bool {
        let mut outcome = "no-rrsig";

        for sig in sigs {
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
                match crypto.verify_rrsig_with_name(&rr, key, owner, rrset, now_secs) {
                    Ok(true) => return true,
                    Ok(false) => outcome = "sig-false",
                    Err(_) => outcome = "sig-err",
                }
            }
        }
        debug!(owner = %owner, ?rtype, outcome, "rrset not authentic");
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
                    if self.rrset_is_authentic(
                        record.name(),
                        record.record_type(),
                        std::slice::from_ref(record),
                        authority,
                        crypto,
                        now_secs,
                    ) =>
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
                    if self.rrset_is_authentic(
                        record.name(),
                        record.record_type(),
                        std::slice::from_ref(record),
                        authority,
                        crypto,
                        now_secs,
                    ) =>
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
        let mut has_data = false;
        let mut has_rrsig = false;
        for record in all_answers {
            match record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    if rrsig.input().type_covered != hickory_proto::rr::RecordType::DNSKEY {
                        has_rrsig = true;
                    }
                }
                _ => has_data = true,
            }
        }

        if !has_data {
            // Empty answers are routed to authenticated denial of existence
            // before reaching here; treat any stray empty RRset as undecided
            // rather than blindly authentic.
            debug!(domain = %domain, "No answer RRset to verify");
            return ValidationResult::Indeterminate;
        }
        if !has_rrsig {
            debug!(domain = %domain, "No RRSIG for RRset — returning Bogus");
            return ValidationResult::Bogus;
        }

        let crypto_verifier = SignatureVerifier;
        let now = now_secs();

        // Group the answer records into RRsets keyed by (owner, type). EVERY
        // RRset must be covered by an RRSIG that verifies against a trusted key
        // (RFC 4035 §5.3.1): verifying just one and returning Secure would let an
        // attacker append unsigned (or untrusted) RRsets to a response carrying a
        // single legitimately-signed RRset and still have the whole answer — and
        // therefore the AD bit — flagged Secure.
        let mut rrsets: Vec<(&Name, hickory_proto::rr::RecordType, Vec<Record>)> = Vec::new();
        for record in all_answers {
            if matches!(record.data(), RData::DNSSEC(DNSSECRData::RRSIG(_))) {
                continue;
            }
            let owner = record.name();
            let rtype = record.record_type();
            match rrsets
                .iter_mut()
                .find(|(o, t, _)| *o == owner && *t == rtype)
            {
                Some(entry) => entry.2.push(record.clone()),
                None => rrsets.push((owner, rtype, vec![record.clone()])),
            }
        }

        for (owner, rtype, records) in &rrsets {
            if !self.rrset_is_authentic(
                owner,
                *rtype,
                records.as_slice(),
                all_answers,
                &crypto_verifier,
                now,
            ) {
                warn!(
                    domain = %domain,
                    owner = %owner,
                    rtype = ?rtype,
                    "answer RRset not covered by a valid RRSIG — returning Bogus"
                );
                return ValidationResult::Bogus;
            }
        }

        debug!(domain = %domain, rrsets = rrsets.len(), "all answer RRsets verified");
        ValidationResult::Secure
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorStats {
    pub timeout_ms: u64,
    pub trust_anchors_count: usize,
}
