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
                upstream_server: None, // Blocked queries don't have upstream
                response_status: Some("BLOCKED".to_string()), // ✅ Custom status for blocked
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
        match self.resolver.resolve(&dns_query).await {
            Ok(resolution) => {
                // Calculate response time in MICROSECONDS (µs) for maximum precision
                let elapsed_micros = start.elapsed().as_micros() as u64;
                let response_time_us = elapsed_micros;

                // Log successful query (ASYNC - fire and forget! ✅)
                let query_log = QueryLog {
                    id: None,
                    domain: request.domain.clone(),
                    record_type: request.record_type.clone(),
                    client_ip: request.client_ip,
                    blocked: false,
                    response_time_ms: Some(response_time_us),
                    cache_hit: resolution.cache_hit,
                    cache_refresh: false,
                    dnssec_status: resolution.dnssec_status.clone(),
                    upstream_server: resolution.upstream_server.clone(),
                    response_status: Some("NOERROR".to_string()), // ✅ Success status
                    timestamp: None,
                };

                // Spawn async task - DON'T WAIT! ✅
                let logger = self.query_log.clone();
                tokio::spawn(async move {
                    if let Err(e) = logger.log_query(&query_log).await {
                        tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log query");
                    }
                });

                Ok(resolution.addresses)
            }
            Err(e) => {
                // ✅ NEW: Log failed queries too!
                let elapsed_micros = start.elapsed().as_micros() as u64;

                // Determine response status from error
                let error_str = e.to_string();
                let response_status =
                    if error_str.contains("NXDomain") || error_str.contains("no records found") {
                        "NXDOMAIN"
                    } else if error_str.contains("timeout") || error_str.contains("Timeout") {
                        "TIMEOUT"
                    } else if error_str.contains("refused") || error_str.contains("Refused") {
                        "REFUSED"
                    } else {
                        "SERVFAIL"
                    };

                let query_log = QueryLog {
                    id: None,
                    domain: request.domain.clone(),
                    record_type: request.record_type.clone(),
                    client_ip: request.client_ip,
                    blocked: false,
                    response_time_ms: Some(elapsed_micros),
                    cache_hit: false,
                    cache_refresh: false,
                    dnssec_status: None,
                    upstream_server: None,
                    response_status: Some(response_status.to_string()), // ✅ Error status
                    timestamp: None,
                };

                // Spawn async task - DON'T WAIT! ✅
                let logger = self.query_log.clone();
                tokio::spawn(async move {
                    if let Err(log_err) = logger.log_query(&query_log).await {
                        tracing::warn!(error = %log_err, "Failed to log error query");
                    }
                });

                Err(e)
            }
        }
    }
}
