use crate::ports::{BlocklistRepository, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DnsRequest, DomainError, QueryLog};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    blocklist: Arc<dyn BlocklistRepository>,
    query_log: Arc<dyn QueryLogRepository>,
}

impl HandleDnsQueryUseCase {
    pub fn new(
        resolver: Arc<dyn DnsResolver>,
        blocklist: Arc<dyn BlocklistRepository>,
        query_log: Arc<dyn QueryLogRepository>,
    ) -> Self {
        Self {
            resolver,
            blocklist,
            query_log,
        }
    }

    pub async fn execute(&self, request: &DnsRequest) -> Result<Vec<IpAddr>, DomainError> {
        let start = Instant::now();

        // Check blocklist
        let is_blocked = self.blocklist.is_blocked(&request.domain).await?;

        if is_blocked {
            // Log blocked query
            let query_log = QueryLog {
                id: None,
                domain: request.domain.clone(),
                record_type: request.record_type.clone(),
                client_ip: request.client_ip,
                blocked: true,
                response_time_ms: Some(start.elapsed().as_millis() as u64),
                timestamp: None,
            };
            self.query_log.log_query(&query_log).await?;

            return Err(DomainError::InvalidDomainName(format!(
                "Domain {} is blocked",
                request.domain
            )));
        }

        // Create DNS query for resolver
        let dns_query = DnsQuery::new(
            request.domain.clone(),
            request.record_type.clone(),
        );

        // Resolve via upstream - agora retorna Vec<IpAddr> direto
        let addresses = self.resolver.resolve(&dns_query).await?;

        // Log successful query
        let query_log = QueryLog {
            id: None,
            domain: request.domain.clone(),
            record_type: request.record_type.clone(),
            client_ip: request.client_ip,
            blocked: false,
            response_time_ms: Some(start.elapsed().as_millis() as u64),
            timestamp: None,
        };
        self.query_log.log_query(&query_log).await?;

        Ok(addresses)
    }
}
