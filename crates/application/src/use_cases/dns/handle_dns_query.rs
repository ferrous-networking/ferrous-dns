use crate::ports::{BlocklistRepository, ClientRepository, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DnsRequest, DomainError, QueryLog, QuerySource};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    blocklist: Arc<dyn BlocklistRepository>,
    query_log: Arc<dyn QueryLogRepository>,
    client_repo: Option<Arc<dyn ClientRepository>>,
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
            client_repo: None,
        }
    }

    pub fn with_client_tracking(mut self, client_repo: Arc<dyn ClientRepository>) -> Self {
        self.client_repo = Some(client_repo);
        self
    }

    pub async fn execute(&self, request: &DnsRequest) -> Result<Vec<IpAddr>, DomainError> {
        let start = Instant::now();

        // Track client (fire-and-forget, don't block DNS response)
        if let Some(client_repo) = &self.client_repo {
            let client_repo = Arc::clone(client_repo);
            let client_ip = request.client_ip;
            tokio::spawn(async move {
                if let Err(e) = client_repo.update_last_seen(client_ip).await {
                    tracing::warn!(error = %e, ip = %client_ip, "Failed to track client");
                }
            });
        }

        let is_blocked = self.blocklist.is_blocked(&request.domain).await?;

        if is_blocked {
            let query_log = QueryLog {
                id: None,
                domain: Arc::clone(&request.domain),
                record_type: request.record_type,
                client_ip: request.client_ip,
                blocked: true,
                response_time_ms: Some(start.elapsed().as_millis() as u64),
                cache_hit: false,
                cache_refresh: false,
                dnssec_status: None,
                upstream_server: None,
                response_status: Some("BLOCKED"),
                timestamp: None,
                query_source: QuerySource::Client,
            };

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

        let dns_query = DnsQuery::new(Arc::clone(&request.domain), request.record_type);

        match self.resolver.resolve(&dns_query).await {
            Ok(resolution) => {
                let response_time_us = start.elapsed().as_micros() as u64;

                let query_log = QueryLog {
                    id: None,
                    domain: Arc::clone(&request.domain),
                    record_type: request.record_type,
                    client_ip: request.client_ip,
                    blocked: false,
                    response_time_ms: Some(response_time_us),
                    cache_hit: resolution.cache_hit,
                    cache_refresh: false,
                    dnssec_status: resolution.dnssec_status,
                    upstream_server: resolution.upstream_server.clone(),
                    response_status: Some("NOERROR"),
                    timestamp: None,
                    query_source: QuerySource::Client,
                };

                let logger = self.query_log.clone();
                tokio::spawn(async move {
                    if let Err(e) = logger.log_query(&query_log).await {
                        tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log query");
                    }
                });

                Ok(resolution.addresses)
            }
            Err(e) => {
                let elapsed_micros = start.elapsed().as_micros() as u64;
                let error_str = e.to_string();
                let response_status: &'static str =
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
                    domain: Arc::clone(&request.domain),
                    record_type: request.record_type,
                    client_ip: request.client_ip,
                    blocked: false,
                    response_time_ms: Some(elapsed_micros),
                    cache_hit: false,
                    cache_refresh: false,
                    dnssec_status: None,
                    upstream_server: None,
                    response_status: Some(response_status),
                    timestamp: None,
                    query_source: QuerySource::Client,
                };

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
