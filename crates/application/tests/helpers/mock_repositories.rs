#![allow(dead_code)]
#![allow(unused_imports)]

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    BlocklistRepository, DnsResolution, DnsResolver, QueryLogRepository,
};
use ferrous_dns_domain::{
    blocklist::BlockedDomain, DnsQuery, DomainError, QueryLog, QueryStats, RecordType,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

// ============================================================================
// Mock DnsResolver
// ============================================================================

#[derive(Clone)]
pub struct MockDnsResolver {
    responses: Arc<RwLock<HashMap<String, DnsResolution>>>,
    should_fail: Arc<RwLock<bool>>,
}

impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            responses: Arc::new(RwLock::new(HashMap::new())),
            should_fail: Arc::new(RwLock::new(false)),
        }
    }

    /// Configura uma resposta mock para um domínio específico
    pub async fn set_response(&self, domain: &str, resolution: DnsResolution) {
        self.responses
            .write()
            .await
            .insert(domain.to_string(), resolution);
    }

    /// Configura múltiplas respostas de uma vez
    pub async fn set_responses(&self, responses: Vec<(&str, DnsResolution)>) {
        let mut map = self.responses.write().await;
        for (domain, resolution) in responses {
            map.insert(domain.to_string(), resolution);
        }
    }

    /// Configura o resolver para falhar
    pub async fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.write().await = should_fail;
    }

    /// Limpa todas as respostas configuradas
    pub async fn clear(&self) {
        self.responses.write().await.clear();
    }
}

impl Default for MockDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if *self.should_fail.read().await {
            return Err(DomainError::InvalidDomainName(
                "Mock resolver failed".to_string(),
            ));
        }

        let responses = self.responses.read().await;
        responses
            .get(query.domain.as_ref())
            .cloned()
            .ok_or_else(|| {
                DomainError::InvalidDomainName(format!("No mock response for {}", query.domain))
            })
    }
}

// ============================================================================
// Mock BlocklistRepository
// ============================================================================

#[derive(Clone)]
pub struct MockBlocklistRepository {
    blocked_domains: Arc<RwLock<Vec<BlockedDomain>>>,
}

impl MockBlocklistRepository {
    pub fn new() -> Self {
        Self {
            blocked_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Cria mock já populado com domínios bloqueados
    pub fn with_blocked_domains(domains: Vec<&str>) -> Self {
        let blocked = domains
            .into_iter()
            .map(|d| BlockedDomain {
                domain: d.to_string(),
                id: None,
                added_at: None,
            })
            .collect();

        Self {
            blocked_domains: Arc::new(RwLock::new(blocked)),
        }
    }

    /// Adiciona domínios bloqueados após criação
    pub async fn add_blocked_domains(&self, domains: Vec<&str>) {
        let mut blocked = self.blocked_domains.write().await;
        for domain in domains {
            blocked.push(BlockedDomain {
                domain: domain.to_string(),
                id: None,
                added_at: None,
            });
        }
    }

    /// Limpa todos os domínios bloqueados
    pub async fn clear(&self) {
        self.blocked_domains.write().await.clear();
    }

    /// Retorna quantidade de domínios bloqueados
    pub async fn count(&self) -> usize {
        self.blocked_domains.read().await.len()
    }
}

impl Default for MockBlocklistRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlocklistRepository for MockBlocklistRepository {
    async fn get_all(&self) -> Result<Vec<BlockedDomain>, DomainError> {
        Ok(self.blocked_domains.read().await.clone())
    }

    async fn add_domain(&self, domain: &BlockedDomain) -> Result<(), DomainError> {
        self.blocked_domains.write().await.push(domain.clone());
        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        let mut domains = self.blocked_domains.write().await;
        domains.retain(|d| d.domain != domain);
        Ok(())
    }

    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError> {
        let domains = self.blocked_domains.read().await;
        Ok(domains.iter().any(|d| d.domain == domain))
    }
}

// ============================================================================
// Mock QueryLogRepository
// ============================================================================

#[derive(Clone)]
pub struct MockQueryLogRepository {
    logs: Arc<RwLock<Vec<QueryLog>>>,
}

impl MockQueryLogRepository {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Retorna todos os logs registrados
    pub async fn get_all_logs(&self) -> Vec<QueryLog> {
        self.logs.read().await.clone()
    }

    /// Retorna quantidade de logs
    pub async fn count(&self) -> usize {
        self.logs.read().await.len()
    }

    /// Retorna logs bloqueados
    pub async fn get_blocked_logs(&self) -> Vec<QueryLog> {
        self.logs
            .read()
            .await
            .iter()
            .filter(|log| log.blocked)
            .cloned()
            .collect()
    }

    /// Retorna logs com cache hit
    pub async fn get_cache_hits(&self) -> Vec<QueryLog> {
        self.logs
            .read()
            .await
            .iter()
            .filter(|log| log.cache_hit)
            .cloned()
            .collect()
    }

    /// Limpa todos os logs
    pub async fn clear(&self) {
        self.logs.write().await.clear();
    }
}

impl Default for MockQueryLogRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QueryLogRepository for MockQueryLogRepository {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        self.logs.write().await.push(query.clone());
        Ok(())
    }

    async fn get_recent(&self, limit: u32) -> Result<Vec<QueryLog>, DomainError> {
        let logs = self.logs.read().await;
        let start = logs.len().saturating_sub(limit as usize);
        Ok(logs[start..].to_vec())
    }

    async fn get_stats(&self) -> Result<QueryStats, DomainError> {
        let logs = self.logs.read().await;
        let queries_total = logs.len() as u64;
        let queries_blocked = logs.iter().filter(|l| l.blocked).count() as u64;

        Ok(QueryStats {
            queries_total,
            queries_blocked,
            unique_clients: 0,
            uptime_seconds: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        })
    }
}

// ============================================================================
// Helper Builders
// ============================================================================

/// Builder para criar DnsResolution facilmente
pub struct DnsResolutionBuilder {
    addresses: Vec<IpAddr>,
    cache_hit: bool,
    dnssec_status: Option<&'static str>,
    cname: Option<String>,
    upstream_server: Option<String>,
}

impl DnsResolutionBuilder {
    pub fn new() -> Self {
        Self {
            addresses: vec![IpAddr::from_str("93.184.216.34").unwrap()],
            cache_hit: false,
            dnssec_status: None,
            cname: None,
            upstream_server: None,
        }
    }

    pub fn with_address(mut self, addr: &str) -> Self {
        self.addresses = vec![IpAddr::from_str(addr).unwrap()];
        self
    }

    pub fn with_addresses(mut self, addrs: Vec<&str>) -> Self {
        self.addresses = addrs.iter().map(|a| IpAddr::from_str(a).unwrap()).collect();
        self
    }

    pub fn cache_hit(mut self) -> Self {
        self.cache_hit = true;
        self
    }

    pub fn cache_miss(mut self) -> Self {
        self.cache_hit = false;
        self
    }

    pub fn with_dnssec(mut self, status: &'static str) -> Self {
        self.dnssec_status = Some(status);
        self
    }

    pub fn with_cname(mut self, cname: &str) -> Self {
        self.cname = Some(cname.to_string());
        self
    }

    pub fn with_upstream(mut self, server: &str) -> Self {
        self.upstream_server = Some(server.to_string());
        self
    }

    pub fn build(self) -> DnsResolution {
        DnsResolution {
            addresses: self.addresses,
            cache_hit: self.cache_hit,
            dnssec_status: self.dnssec_status,
            cname: self.cname,
            upstream_server: self.upstream_server,
        }
    }
}

impl Default for DnsResolutionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_dns_resolver() {
        let resolver = MockDnsResolver::new();

        let resolution = DnsResolutionBuilder::new()
            .with_address("1.1.1.1")
            .cache_hit()
            .build();

        resolver.set_response("example.com", resolution).await;

        let query = DnsQuery {
            domain: "example.com".into(),
            record_type: RecordType::A,
        };

        let result = resolver.resolve(&query).await;
        assert!(result.is_ok());
        assert!(result.unwrap().cache_hit);
    }

    #[tokio::test]
    async fn test_mock_blocklist() {
        let blocklist =
            MockBlocklistRepository::with_blocked_domains(vec!["ads.com", "tracker.com"]);

        assert!(blocklist.is_blocked("ads.com").await.unwrap());
        assert!(!blocklist.is_blocked("google.com").await.unwrap());

        assert_eq!(blocklist.count().await, 2);
    }

    #[tokio::test]
    async fn test_mock_query_log() {
        let log_repo = MockQueryLogRepository::new();

        let log = QueryLog {
            id: None,
            domain: "test.com".into(),
            record_type: RecordType::A,
            client_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            blocked: false,
            response_time_ms: Some(10),
            cache_hit: true,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: None,
            response_status: None,
            timestamp: None,
            query_source: Default::default(),
        };

        log_repo.log_query(&log).await.unwrap();

        assert_eq!(log_repo.count().await, 1);
        assert_eq!(log_repo.get_cache_hits().await.len(), 1);
    }
}
