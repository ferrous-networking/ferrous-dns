use crate::dns::dnssec::cache::DnssecCache;
use crate::dns::dnssec::crypto::SignatureVerifier;
use crate::dns::dnssec::trust_anchor::TrustAnchorStore;
use crate::dns::dnssec::types::{DnskeyRecord, DsRecord, RrsigRecord};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
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
        let ds_records = self.query_ds(child_domain).await?;

        if ds_records.is_empty() {
            debug!(domain = %child_domain, "No DS records found (insecure)");
            return Err(DomainError::InvalidDnsResponse(
                "No DS records found".into(),
            ));
        }

        let dnskey_records = self.query_dnskey(child_domain).await?;

        if dnskey_records.is_empty() {
            warn!(domain = %child_domain, "No DNSKEY records found");
            return Err(DomainError::InvalidDnsResponse(
                "No DNSKEY records found".into(),
            ));
        }

        let mut validated_keys = Vec::new();

        for ds in &ds_records {
            for dnskey in &dnskey_records {
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
            Ok(_upstream_result) => {
                let records = Vec::new();

                debug!(
                    domain = %domain,
                    count = records.len(),
                    "DS query successful, caching result"
                );

                self.dnssec_cache.cache_ds(domain, records.clone(), 3600);

                Ok(records)
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DS query failed");
                Err(e)
            }
        }
    }

    async fn query_dnskey(&self, domain: &str) -> Result<Vec<DnskeyRecord>, DomainError> {
        if let Some(keys) = self.dnssec_cache.get_dnskey(domain) {
            debug!(
                domain = %domain,
                count = keys.len(),
                "DNSKEY cache hit"
            );
            return Ok(keys);
        }

        debug!(domain = %domain, "DNSKEY cache miss, querying DNS");

        let result = self
            .pool_manager
            .query(domain, &RecordType::DNSKEY, 5000)
            .await;

        match result {
            Ok(_upstream_result) => {
                let keys = Vec::new();

                debug!(
                    domain = %domain,
                    count = keys.len(),
                    "DNSKEY query successful, caching result"
                );

                self.dnssec_cache.cache_dnskey(domain, keys.clone(), 3600);

                Ok(keys)
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DNSKEY query failed");
                Err(e)
            }
        }
    }

    #[allow(dead_code)]
    async fn query_rrsig(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Vec<RrsigRecord>, DomainError> {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Querying RRSIG records"
        );

        Ok(Vec::new())
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
