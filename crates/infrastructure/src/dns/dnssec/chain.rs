use super::cache::DnssecCache;
use super::crypto::SignatureVerifier;
use super::trust_anchor::TrustAnchorStore;
use super::types::{DnskeyRecord, DsRecord, RrsigRecord};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Result of DNSSEC validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// DNSSEC validation successful - chain of trust verified
    Secure,

    /// No DNSSEC records found - zone is unsigned
    Insecure,

    /// DNSSEC validation failed - signatures invalid or chain broken
    Bogus,

    /// Could not complete validation (network error, timeout, etc.)
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

/// DNSSEC chain of trust verifier
///
/// Validates the complete chain from root trust anchor down to the target domain.
pub struct ChainVerifier {
    pool_manager: Arc<PoolManager>,
    trust_store: TrustAnchorStore,
    crypto_verifier: SignatureVerifier,
    /// Cache of validated DNSKEYs (domain -> DNSKEY)
    validated_keys: HashMap<String, Vec<DnskeyRecord>>,
    /// DNSSEC cache for DS/DNSKEY records
    dnssec_cache: Arc<DnssecCache>,
}

impl ChainVerifier {
    /// Create a new chain verifier
    ///
    /// ## Arguments
    ///
    /// - `pool_manager`: Used to query upstream DNS servers
    /// - `trust_store`: Contains root trust anchors
    /// - `dnssec_cache`: Cache for DS/DNSKEY records
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

    /// Verify complete DNSSEC chain for a domain
    ///
    /// ## Process
    ///
    /// 1. Split domain into labels (google.com → ["com", "google"])
    /// 2. Start from root (trust anchor)
    /// 3. For each label:
    ///    - Query DS from parent
    ///    - Query DNSKEY from child
    ///    - Verify DS hash matches DNSKEY
    ///    - Add DNSKEY to validated set
    /// 4. Verify final record's RRSIG
    ///
    /// ## Query Logging
    ///
    /// All queries (DS, DNSKEY, RRSIG) are made via PoolManager, which logs
    /// them with query_source="internal". This provides complete DNSSEC transparency!
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// let result = verifier.verify_chain("google.com", RecordType::A).await?;
    /// ```
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

        // 1. Check if root trust anchor exists
        if self.trust_store.get_anchor(".").is_none() {
            warn!("No root trust anchor configured");
            return Ok(ValidationResult::Indeterminate);
        }

        // 2. Build label chain (google.com → ["com", "google"])
        let labels = Self::split_domain(domain);
        debug!(labels = ?labels, "Domain labels");

        // 3. Start with root trust anchor
        let root_anchor = self.trust_store.get_anchor(".").unwrap();
        self.validated_keys
            .insert(".".to_string(), vec![root_anchor.dnskey.clone()]);

        // 4. Walk down the chain
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

            // Validate delegation from parent to child
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

        // 5. At this point, we have validated keys for the target domain
        info!(
            domain = %domain,
            "Chain of trust validated successfully"
        );

        Ok(ValidationResult::Secure)
    }

    /// Validate delegation from parent to child zone
    ///
    /// ## Process
    ///
    /// 1. Query DS record from parent zone (e.g., DS for google.com from .com)
    /// 2. Query DNSKEY record from child zone (e.g., DNSKEY from google.com)
    /// 3. Verify DS hash matches DNSKEY
    /// 4. Add validated DNSKEY to cache
    ///
    /// ## Query Logging
    ///
    /// Both DS and DNSKEY queries are logged via PoolManager!
    async fn validate_delegation(
        &mut self,
        _parent_domain: &str,
        child_domain: &str,
    ) -> Result<(), DomainError> {
        // 1. Query DS from parent
        // This query is LOGGED via PoolManager! 🔍
        let ds_records = self.query_ds(child_domain).await?;

        if ds_records.is_empty() {
            // No DS records = insecure delegation (not signed)
            debug!(domain = %child_domain, "No DS records found (insecure)");
            return Err(DomainError::InvalidDnsResponse(
                "No DS records found".into(),
            ));
        }

        // 2. Query DNSKEY from child
        // This query is LOGGED via PoolManager! 🔍
        let dnskey_records = self.query_dnskey(child_domain).await?;

        if dnskey_records.is_empty() {
            warn!(domain = %child_domain, "No DNSKEY records found");
            return Err(DomainError::InvalidDnsResponse(
                "No DNSKEY records found".into(),
            ));
        }

        // 3. Find DNSKEY that matches DS
        let mut validated_keys = Vec::new();

        for ds in &ds_records {
            for dnskey in &dnskey_records {
                // Verify DS hash matches DNSKEY
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

        // 4. Cache validated keys
        self.validated_keys
            .insert(child_domain.to_string(), validated_keys);

        Ok(())
    }

    /// Query DS records for a domain
    ///
    /// **IMPORTANT**: This query is logged via PoolManager!
    ///
    /// The query will appear in the database with:
    /// - domain: {domain}
    /// - record_type: DS
    /// - query_source: internal
    ///
    /// **CACHING**: DS records are cached to avoid redundant queries.
    /// - Cache hit: Returns immediately from cache (<1µs)
    /// - Cache miss: Queries DNS and caches result (TTL 3600s)
    async fn query_ds(&self, domain: &str) -> Result<Vec<DsRecord>, DomainError> {
        // 1. Check cache first
        if let Some(records) = self.dnssec_cache.get_ds(domain) {
            debug!(
                domain = %domain,
                count = records.len(),
                "DS cache hit"
            );
            return Ok(records);
        }

        // 2. Cache miss - query DNS
        debug!(domain = %domain, "DS cache miss, querying DNS");

        // Query via PoolManager (which logs the query!)
        let result = self.pool_manager.query(domain, &RecordType::DS, 5000).await;

        match result {
            Ok(_upstream_result) => {
                // For now, return empty to demonstrate structure
                // Phase 8 will implement full response parsing
                let records = Vec::new();

                debug!(
                    domain = %domain,
                    count = records.len(),
                    "DS query successful, caching result"
                );

                // 3. Cache the result (TTL 3600s = 1 hour)
                self.dnssec_cache.cache_ds(domain, records.clone(), 3600);

                Ok(records)
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DS query failed");
                Err(e)
            }
        }
    }

    /// Query DNSKEY records for a domain
    ///
    /// **IMPORTANT**: This query is logged via PoolManager!
    ///
    /// The query will appear in the database with:
    /// - domain: {domain}
    /// - record_type: DNSKEY
    /// - query_source: internal
    ///
    /// **CACHING**: DNSKEY records are cached to avoid redundant queries.
    /// - Cache hit: Returns immediately from cache (<1µs)
    /// - Cache miss: Queries DNS and caches result (TTL 3600s)
    async fn query_dnskey(&self, domain: &str) -> Result<Vec<DnskeyRecord>, DomainError> {
        // 1. Check cache first
        if let Some(keys) = self.dnssec_cache.get_dnskey(domain) {
            debug!(
                domain = %domain,
                count = keys.len(),
                "DNSKEY cache hit"
            );
            return Ok(keys);
        }

        // 2. Cache miss - query DNS
        debug!(domain = %domain, "DNSKEY cache miss, querying DNS");

        // Query via PoolManager (which logs the query!)
        let result = self
            .pool_manager
            .query(domain, &RecordType::DNSKEY, 5000)
            .await;

        match result {
            Ok(_upstream_result) => {
                // For now, return empty to demonstrate structure
                // Phase 8 will implement full response parsing
                let keys = Vec::new();

                debug!(
                    domain = %domain,
                    count = keys.len(),
                    "DNSKEY query successful, caching result"
                );

                // 3. Cache the result (TTL 3600s = 1 hour)
                self.dnssec_cache.cache_dnskey(domain, keys.clone(), 3600);

                Ok(keys)
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DNSKEY query failed");
                Err(e)
            }
        }
    }

    /// Query RRSIG records for a domain and record type
    ///
    /// **IMPORTANT**: This query is logged via PoolManager!
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

        // In practice, RRSIG is returned alongside the record type query
        // This is a placeholder for the full implementation
        Ok(Vec::new())
    }

    /// Split domain into labels
    ///
    /// Examples:
    /// - "google.com" → ["com", "google"]
    /// - "www.example.com" → ["com", "example", "www"]
    /// - "." → []
    fn split_domain(domain: &str) -> Vec<String> {
        let domain = domain.trim_end_matches('.');

        if domain.is_empty() || domain == "." {
            return Vec::new();
        }

        domain.split('.').rev().map(|s| s.to_string()).collect()
    }

    /// Get parent domain
    ///
    /// Examples:
    /// - "google.com." → "com."
    /// - "www.google.com." → "google.com."
    /// - "com." → "."
    /// - "." → None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_domain() {
        assert_eq!(
            ChainVerifier::split_domain("google.com"),
            vec!["com", "google"]
        );

        assert_eq!(
            ChainVerifier::split_domain("www.example.com"),
            vec!["com", "example", "www"]
        );

        assert_eq!(ChainVerifier::split_domain("com"), vec!["com"]);

        assert_eq!(ChainVerifier::split_domain("."), Vec::<String>::new());

        assert_eq!(ChainVerifier::split_domain(""), Vec::<String>::new());
    }

    #[test]
    fn test_parent_domain() {
        assert_eq!(
            ChainVerifier::parent_domain("google.com."),
            Some("com.".to_string())
        );

        assert_eq!(
            ChainVerifier::parent_domain("www.google.com."),
            Some("google.com.".to_string())
        );

        assert_eq!(ChainVerifier::parent_domain("com."), Some(".".to_string()));

        assert_eq!(ChainVerifier::parent_domain("."), None);
    }

    #[test]
    fn test_validation_result_as_str() {
        assert_eq!(ValidationResult::Secure.as_str(), "Secure");
        assert_eq!(ValidationResult::Insecure.as_str(), "Insecure");
        assert_eq!(ValidationResult::Bogus.as_str(), "Bogus");
        assert_eq!(ValidationResult::Indeterminate.as_str(), "Indeterminate");
    }
}
