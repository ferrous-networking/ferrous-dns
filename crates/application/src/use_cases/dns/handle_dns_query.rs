use crate::ports::{
    BlockFilterEnginePort, ClientRepository, DnsResolution, DnsResolver, FilterDecision,
    QueryLogRepository,
};
use ferrous_dns_domain::{DnsQuery, DnsRequest, DomainError, QueryLog, QuerySource};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

thread_local! {
    static LAST_SEEN_TRACKER: RefCell<HashMap<IpAddr, Instant>> =
        RefCell::new(HashMap::new());
}

pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    block_filter: Arc<dyn BlockFilterEnginePort>,
    query_log: Arc<dyn QueryLogRepository>,
    client_repo: Option<Arc<dyn ClientRepository>>,
    client_tracking_interval: Duration,
}

impl HandleDnsQueryUseCase {
    pub fn new(
        resolver: Arc<dyn DnsResolver>,
        block_filter: Arc<dyn BlockFilterEnginePort>,
        query_log: Arc<dyn QueryLogRepository>,
    ) -> Self {
        Self {
            resolver,
            block_filter,
            query_log,
            client_repo: None,
            client_tracking_interval: Duration::from_secs(60),
        }
    }

    pub fn with_client_tracking(
        mut self,
        client_repo: Arc<dyn ClientRepository>,
        interval_secs: u64,
    ) -> Self {
        self.client_repo = Some(client_repo);
        self.client_tracking_interval = Duration::from_secs(interval_secs);
        self
    }

    pub async fn execute(&self, request: &DnsRequest) -> Result<DnsResolution, DomainError> {
        let start = Instant::now();

        if let Some(client_repo) = &self.client_repo {
            let needs_update = LAST_SEEN_TRACKER.with(|t| {
                let mut tracker = t.borrow_mut();
                let now = Instant::now();
                match tracker.get(&request.client_ip) {
                    Some(&last) if now.duration_since(last) < self.client_tracking_interval => {
                        false
                    }
                    _ => {
                        tracker.insert(request.client_ip, now);
                        true
                    }
                }
            });

            if needs_update {
                let client_repo = Arc::clone(client_repo);
                let client_ip = request.client_ip;
                tokio::spawn(async move {
                    if let Err(e) = client_repo.update_last_seen(client_ip).await {
                        tracing::warn!(error = %e, ip = %client_ip, "Failed to track client");
                    }
                });
            }
        }

        let group_id = self.block_filter.resolve_group(request.client_ip);
        let decision = self.block_filter.check(&request.domain, group_id);

        if matches!(decision, FilterDecision::Block) {
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
                group_id: Some(group_id),
            };

            if let Err(e) = self.query_log.log_query(&query_log).await {
                tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log blocked query");
            }

            return Err(DomainError::Blocked);
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
                    group_id: Some(group_id),
                };

                if let Err(e) = self.query_log.log_query(&query_log).await {
                    tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log query");
                }

                Ok(resolution)
            }
            Err(e) => {
                let elapsed_micros = start.elapsed().as_micros() as u64;
                let response_status: &'static str = match &e {
                    DomainError::NxDomain => "NXDOMAIN",
                    DomainError::QueryTimeout => "TIMEOUT",
                    _ => "SERVFAIL",
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
                    group_id: Some(group_id),
                };

                if let Err(log_err) = self.query_log.log_query(&query_log).await {
                    tracing::warn!(error = %log_err, "Failed to log error query");
                }

                Err(e)
            }
        }
    }
}
