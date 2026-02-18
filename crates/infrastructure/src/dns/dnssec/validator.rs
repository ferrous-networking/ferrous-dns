use super::cache::DnssecCache;
use super::trust_anchor::TrustAnchorStore;
use super::validation::{ChainVerifier, ValidationResult};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use std::sync::Arc;
use tracing::{debug, info};

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
}

#[derive(Debug, Clone)]
pub struct ValidatorStats {
    pub timeout_ms: u64,
    pub trust_anchors_count: usize,
}
