use crate::dns::dnssec::cache::DnssecCache;
use crate::dns::dnssec::crypto::SignatureVerifier;
use crate::dns::dnssec::trust_anchor::TrustAnchorStore;
use crate::dns::dnssec::types::{DnskeyRecord, DsRecord, RrsigRecord};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::{RData, Record};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Secure,

    Insecure,

    Bogus,

    Indeterminate,
}

impl ValidationResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        }
    }
}

struct DnskeyQueryResult {
    keys: Vec<DnskeyRecord>,
    rrsigs: Vec<RrsigRecord>,
    raw_records: Vec<Record>,
}

pub struct ChainVerifier {
    pool_manager: Arc<PoolManager>,
    trust_store: TrustAnchorStore,
    crypto_verifier: SignatureVerifier,

    validated_keys: HashMap<String, Vec<DnskeyRecord>>,

    dnssec_cache: Arc<DnssecCache>,
}

impl ChainVerifier {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        trust_store: TrustAnchorStore,
        dnssec_cache: Arc<DnssecCache>,
    ) -> Self {
        Self {
            pool_manager,
            trust_store,
            crypto_verifier: SignatureVerifier,
            validated_keys: HashMap::new(),
            dnssec_cache,
        }
    }

    pub async fn verify_chain(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidationResult, DomainError> {
        info!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC chain verification"
        );

        if self.trust_store.get_anchor(".").is_none() {
            warn!("No root trust anchor configured");
            return Ok(ValidationResult::Indeterminate);
        }

        let labels = Self::split_domain(domain);
        debug!(labels = ?labels, "Domain labels");

        let root_anchor = self.trust_store.get_anchor(".").unwrap();
        self.validated_keys
            .insert(".".to_string(), vec![root_anchor.dnskey.clone()]);

        let mut current_domain = String::from(".");

        for label in &labels {
            let child_domain = if current_domain == "." {
                format!("{}.", label)
            } else {
                format!("{}.{}", label, current_domain)
            };

            debug!(
                parent = %current_domain,
                child = %child_domain,
                "Validating delegation"
            );

            match self
                .validate_delegation(&current_domain, &child_domain)
                .await
            {
                Ok(()) => {
                    debug!(domain = %child_domain, "Delegation validated");
                }
                Err(e) => {
                    warn!(
                        parent = %current_domain,
                        child = %child_domain,
                        error = %e,
                        "Delegation validation failed"
                    );
                    return Ok(ValidationResult::Bogus);
                }
            }

            current_domain = child_domain;
        }

        info!(
            domain = %domain,
            "Chain of trust validated successfully"
        );

        Ok(ValidationResult::Secure)
    }

    async fn validate_delegation(
        &mut self,
        _parent_domain: &str,
        child_domain: &str,
    ) -> Result<(), DomainError> {
        // 1. Query DS records for child zone
        let ds_records = self.query_ds(child_domain).await?;

        if ds_records.is_empty() {
            debug!(domain = %child_domain, "No DS records found (insecure delegation)");
            return Err(DomainError::InvalidDnsResponse(
                "No DS records found".into(),
            ));
        }

        // 2. Query DNSKEY records (also extracts RRSIGs from same response)
        let dnskey_result = self.query_dnskey(child_domain).await?;

        if dnskey_result.keys.is_empty() {
            warn!(domain = %child_domain, "No DNSKEY records found");
            return Err(DomainError::InvalidDnsResponse(
                "No DNSKEY records found".into(),
            ));
        }

        // 3. Verify DS → DNSKEY hash: find keys authenticated by parent's DS
        let mut validated_keys = Vec::new();

        for ds in &ds_records {
            for dnskey in &dnskey_result.keys {
                match self.crypto_verifier.verify_ds(ds, dnskey, child_domain) {
                    Ok(true) => {
                        debug!(
                            domain = %child_domain,
                            key_tag = dnskey.calculate_key_tag(),
                            "DS validation successful"
                        );
                        validated_keys.push(dnskey.clone());
                        break;
                    }
                    Ok(false) => {
                        debug!(
                            domain = %child_domain,
                            ds_tag = ds.key_tag,
                            key_tag = dnskey.calculate_key_tag(),
                            "DS does not match DNSKEY"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "DS verification error");
                    }
                }
            }
        }

        if validated_keys.is_empty() {
            warn!(
                domain = %child_domain,
                "No DNSKEY matched any DS record"
            );
            return Err(DomainError::InvalidDnsResponse(
                "No matching DNSKEY for DS".into(),
            ));
        }

        // 4. Verify RRSIG over DNSKEY set using the DS-authenticated keys
        // The DNSKEY RRSet is signed by the zone's own KSK (which we just validated via DS)
        if !dnskey_result.rrsigs.is_empty() && !dnskey_result.raw_records.is_empty() {
            let mut rrsig_ok = false;

            'outer: for rrsig in &dnskey_result.rrsigs {
                for key in &validated_keys {
                    match self.crypto_verifier.verify_rrsig(
                        rrsig,
                        key,
                        child_domain,
                        &dnskey_result.raw_records,
                    ) {
                        Ok(true) => {
                            debug!(
                                domain = %child_domain,
                                key_tag = key.calculate_key_tag(),
                                "DNSKEY RRSIG verified"
                            );
                            rrsig_ok = true;
                            break 'outer;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(error = %e, "RRSIG verification error");
                        }
                    }
                }
            }

            if !rrsig_ok {
                warn!(
                    domain = %child_domain,
                    "DNSKEY RRSIG verification failed for all keys"
                );
                return Err(DomainError::InvalidDnsResponse(
                    "DNSKEY RRSIG verification failed".into(),
                ));
            }
        } else {
            debug!(
                domain = %child_domain,
                rrsigs = dnskey_result.rrsigs.len(),
                raw_records = dnskey_result.raw_records.len(),
                "Skipping RRSIG verification (cache hit or no RRSIGs in response)"
            );
        }

        self.validated_keys
            .insert(child_domain.to_string(), validated_keys);

        Ok(())
    }

    async fn query_ds(&self, domain: &str) -> Result<Vec<DsRecord>, DomainError> {
        if let Some(records) = self.dnssec_cache.get_ds(domain) {
            debug!(
                domain = %domain,
                count = records.len(),
                "DS cache hit"
            );
            return Ok(records);
        }

        debug!(domain = %domain, "DS cache miss, querying DNS");

        let result = self.pool_manager.query(domain, &RecordType::DS, 5000).await;

        match result {
            Ok(upstream_result) => {
                let mut records = Vec::new();

                for record in &upstream_result.response.raw_answers {
                    if let RData::DNSSEC(DNSSECRData::DS(ds)) = record.data() {
                        records.push(DsRecord {
                            key_tag: ds.key_tag(),
                            algorithm: u8::from(ds.algorithm()),
                            digest_type: u8::from(ds.digest_type()),
                            digest: ds.digest().to_vec(),
                        });
                    }
                }

                debug!(
                    domain = %domain,
                    count = records.len(),
                    "DS query successful, caching result"
                );

                let ttl = upstream_result.response.min_ttl.unwrap_or(3600);
                self.dnssec_cache.cache_ds(domain, records.clone(), ttl);

                Ok(records)
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DS query failed");
                Err(e)
            }
        }
    }

    async fn query_dnskey(&self, domain: &str) -> Result<DnskeyQueryResult, DomainError> {
        if let Some(keys) = self.dnssec_cache.get_dnskey(domain) {
            debug!(
                domain = %domain,
                count = keys.len(),
                "DNSKEY cache hit"
            );
            // Cache hit: return keys without raw_records/rrsigs (RRSIG check skipped)
            return Ok(DnskeyQueryResult {
                keys,
                rrsigs: vec![],
                raw_records: vec![],
            });
        }

        debug!(domain = %domain, "DNSKEY cache miss, querying DNS");

        let result = self
            .pool_manager
            .query(domain, &RecordType::DNSKEY, 5000)
            .await;

        match result {
            Ok(upstream_result) => {
                let mut keys = Vec::new();
                let mut rrsigs = Vec::new();
                let mut raw_records = Vec::new();

                for record in &upstream_result.response.raw_answers {
                    match record.data() {
                        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => {
                            let pk = dnskey.public_key();
                            keys.push(DnskeyRecord {
                                flags: dnskey.flags(),
                                protocol: 3,
                                algorithm: u8::from(<dyn PublicKey>::algorithm(pk)),
                                public_key: <dyn PublicKey>::public_bytes(pk).to_vec(),
                            });
                            raw_records.push(record.clone());
                        }
                        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                            let input = rrsig.input();
                            // Only collect RRSIGs that cover the DNSKEY type
                            if input.type_covered != hickory_proto::rr::RecordType::DNSKEY {
                                continue;
                            }
                            let Some(type_covered) =
                                RecordTypeMapper::from_hickory(input.type_covered)
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
                        _ => {}
                    }
                }

                debug!(
                    domain = %domain,
                    keys = keys.len(),
                    rrsigs = rrsigs.len(),
                    "DNSKEY query successful, caching result"
                );

                let ttl = upstream_result.response.min_ttl.unwrap_or(3600);
                self.dnssec_cache.cache_dnskey(domain, keys.clone(), ttl);

                Ok(DnskeyQueryResult {
                    keys,
                    rrsigs,
                    raw_records,
                })
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DNSKEY query failed");
                Err(e)
            }
        }
    }

    fn split_domain(domain: &str) -> Vec<String> {
        let domain = domain.trim_end_matches('.');

        if domain.is_empty() || domain == "." {
            return Vec::new();
        }

        domain.split('.').rev().map(|s| s.to_string()).collect()
    }

    #[allow(dead_code)]
    fn parent_domain(domain: &str) -> Option<String> {
        let domain = domain.trim_end_matches('.');

        if domain.is_empty() || domain == "." {
            return None;
        }

        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() <= 1 {
            return Some(".".to_string());
        }

        Some(format!("{}.", parts[1..].join(".")))
    }
}
