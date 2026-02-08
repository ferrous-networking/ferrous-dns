use super::cache::DnssecCache;
use super::chain::{ChainVerifier, ValidationResult};
use super::trust_anchor::TrustAnchorStore;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use std::sync::Arc;
use tracing::{debug, info};

/// Validated DNS response
///
/// Contains the DNS records along with DNSSEC validation status.
#[derive(Debug, Clone)]
pub struct ValidatedResponse {
    /// Validation status (Secure, Insecure, Bogus, Indeterminate)
    pub validation_status: ValidationResult,

    /// DNS records (addresses, CNAME, etc.)
    pub records: Vec<String>,

    /// Domain that was queried
    pub domain: String,

    /// Record type that was queried
    pub record_type: RecordType,

    /// Response time in milliseconds
    pub response_time_ms: u64,

    /// Upstream server used
    pub upstream_server: Option<String>,
}

impl ValidatedResponse {
    /// Create a new validated response
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

    /// Check if DNSSEC validation was successful
    pub fn is_secure(&self) -> bool {
        matches!(self.validation_status, ValidationResult::Secure)
    }

    /// Check if zone is unsigned (no DNSSEC)
    pub fn is_insecure(&self) -> bool {
        matches!(self.validation_status, ValidationResult::Insecure)
    }

    /// Check if DNSSEC validation failed
    pub fn is_bogus(&self) -> bool {
        matches!(self.validation_status, ValidationResult::Bogus)
    }
}

/// DNSSEC Validator - Main API
///
/// The primary interface for DNSSEC validation. Orchestrates chain verification,
/// cryptographic validation, and query logging.
///
/// ## Example
///
/// ```rust,no_run
/// use ferrous_dns_infrastructure::dns::dnssec::DnssecValidator;
///
/// let validator = DnssecValidator::new(pool_manager);
///
/// let response = validator
///     .validate_query("google.com", RecordType::A)
///     .await?;
///
/// if response.is_secure() {
///     println!("DNSSEC valid!");
/// }
/// ```
pub struct DnssecValidator {
    /// Pool manager for DNS queries
    pool_manager: Arc<PoolManager>,

    /// Chain verifier for DNSSEC validation
    chain_verifier: ChainVerifier,

    /// Query timeout in milliseconds
    timeout_ms: u64,
}

impl DnssecValidator {
    /// Create a new DNSSEC validator
    ///
    /// ## Arguments
    ///
    /// - `pool_manager`: Used to query upstream DNS servers
    ///
    /// ## Default Settings
    ///
    /// - Trust anchors: Root KSK 20326
    /// - Timeout: 5000ms
    /// - Cache: Creates internal cache for DS/DNSKEY records
    ///
    /// ## Note
    ///
    /// If you want to share cache with other components, use `with_cache()` instead.
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

    /// Create validator with shared cache
    ///
    /// Use this when you want to share the DNSSEC cache with other components.
    ///
    /// ## Arguments
    ///
    /// - `pool_manager`: Used to query upstream DNS servers
    /// - `dnssec_cache`: Shared cache for DS/DNSKEY records
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// let cache = Arc::new(DnssecCache::new());
    /// let validator = DnssecValidator::with_cache(pool_manager, cache.clone());
    /// // Other components can use cache.clone() for shared access
    /// ```
    pub fn with_cache(pool_manager: Arc<PoolManager>, dnssec_cache: Arc<DnssecCache>) -> Self {
        let trust_store = TrustAnchorStore::new();
        let chain_verifier = ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms: 5000,
        }
    }

    /// Create validator with custom trust anchors
    pub fn with_trust_store(pool_manager: Arc<PoolManager>, trust_store: TrustAnchorStore) -> Self {
        let dnssec_cache = Arc::new(DnssecCache::new());
        let chain_verifier = ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms: 5000,
        }
    }

    /// Create validator with custom trust anchors and shared cache
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

    /// Set query timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Validate a DNS query with DNSSEC
    ///
    /// ## Process
    ///
    /// 1. Query DNS record (A, AAAA, etc.)
    /// 2. Verify DNSSEC chain of trust
    /// 3. Return validated response
    ///
    /// ## Query Logging
    ///
    /// ALL queries are logged via PoolManager:
    /// - Main query (A, AAAA, etc.) → logged
    /// - DS queries → logged (query_source="internal")
    /// - DNSKEY queries → logged (query_source="internal")
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// let response = validator
    ///     .validate_query("google.com", RecordType::A)
    ///     .await?;
    ///
    /// match response.validation_status {
    ///     ValidationResult::Secure => println!("✅ DNSSEC valid"),
    ///     ValidationResult::Bogus => println!("❌ DNSSEC invalid"),
    ///     _ => println!("No DNSSEC"),
    /// }
    /// ```
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

        // 1. Query DNS record (logged via PoolManager!)
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

        // 2. Verify DNSSEC chain of trust
        // This will query DS/DNSKEY records (all logged!)
        let validation_status = self
            .chain_verifier
            .verify_chain(domain, record_type)
            .await?;

        let elapsed = start.elapsed().as_millis() as u64;

        info!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = elapsed,
            "DNSSEC validation completed"
        );

        // 3. Build response
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

    /// Validate query and return simple result
    ///
    /// Simpler API that returns only the validation status.
    pub async fn validate_simple(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidationResult, DomainError> {
        let response = self.validate_query(domain, record_type).await?;
        Ok(response.validation_status)
    }

    /// Check if a domain has DNSSEC enabled
    ///
    /// Queries DS record to check if zone is signed.
    pub async fn has_dnssec(&self, domain: &str) -> Result<bool, DomainError> {
        debug!(domain = %domain, "Checking DNSSEC availability");

        // Query DS record (logged!)
        let result = self
            .pool_manager
            .query(domain, &RecordType::DS, self.timeout_ms)
            .await;

        match result {
            Ok(_upstream_result) => {
                // If we got a response, check if it has DS records
                // For now, we assume any successful response means DNSSEC exists
                debug!(domain = %domain, "DNSSEC check: DS query successful");
                Ok(true)
            }
            Err(_) => {
                // No DS records = no DNSSEC
                debug!(domain = %domain, "DNSSEC check: No DS records");
                Ok(false)
            }
        }
    }

    /// Get validator statistics
    pub fn stats(&self) -> ValidatorStats {
        ValidatorStats {
            timeout_ms: self.timeout_ms,
            trust_anchors_count: 1, // Root KSK
        }
    }
}

/// Validator statistics
#[derive(Debug, Clone)]
pub struct ValidatorStats {
    pub timeout_ms: u64,
    pub trust_anchors_count: usize,
}
