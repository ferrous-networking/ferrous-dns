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
            // Log blocked query (ASYNC - fire and forget! ✅)
            let query_log = QueryLog {
                id: None,
                domain: request.domain.clone(),
                record_type: request.record_type.clone(),
                client_ip: request.client_ip,
                blocked: true,
                response_time_ms: Some(start.elapsed().as_millis() as u64),
                cache_hit: false,
                cache_refresh: false,
                dnssec_status: None,
                timestamp: None,
            };
            
            // Spawn async task - DON'T WAIT! ✅
            let logger = self.query_log.clone();
            tokio::spawn(async move {
                if let Err(e) = logger.log_query(&query_log).await {
                    tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log blocked query");
                }
            });

            return Err(DomainError::InvalidDomainName(format!(
                "Domain {} is blocked",
                request.domain
            )));
        }

        // Create DNS query for resolver
        let dns_query = DnsQuery::new(request.domain.clone(), request.record_type.clone());

        // Resolve via upstream/cache - retorna DnsResolution com cache_hit info
        let resolution = self.resolver.resolve(&dns_query).await?;

        // Calculate response time in microseconds for sub-millisecond precision
        let elapsed_micros = start.elapsed().as_micros() as u64;
        
        // Convert to milliseconds but preserve sub-ms precision
        let response_time_ms = if elapsed_micros < 1000 {
            elapsed_micros  // Store microseconds directly when < 1ms
        } else {
            elapsed_micros / 1000  // Convert to milliseconds when >= 1ms
        };

        // Log successful query (ASYNC - fire and forget! ✅)
        let query_log = QueryLog {
            id: None,
            domain: request.domain.clone(),
            record_type: request.record_type.clone(),
            client_ip: request.client_ip,
            blocked: false,
            response_time_ms: Some(response_time_ms),
            cache_hit: resolution.cache_hit,
            cache_refresh: false,
            dnssec_status: resolution.dnssec_status,
            timestamp: None,
        };
        
        // Spawn async task - DON'T WAIT! ✅
        let logger = self.query_log.clone();
        tokio::spawn(async move {
            if let Err(e) = logger.log_query(&query_log).await {
                tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log query");
            }
        });

        // Return immediately! ✅
        Ok(resolution.addresses)
    }
}
