use super::coarse_timer::coarse_now_ns;
use super::dga_guard::{DgaAnalysisEvent, DgaGuard, DgaVerdict};
use super::nxdomain_hijack_guard::NxdomainHijackGuard;
use super::rate_limiter::{DnsRateLimiter, RateLimitDecision};
use super::rebinding_guard::RebindingGuard;
use super::response_ip_filter_guard::ResponseIpFilterGuard;
use super::tsc_timer;
use super::tunneling_guard::{TunnelingAnalysisEvent, TunnelingGuard, TunnelingVerdict};
use crate::ports::{
    BlockFilterEnginePort, ClientRepository, DgaFlagStore, DnsResolution, DnsResolver,
    FilterDecision, NxdomainHijackIpStore, QueryLogRepository, ResponseIpFilterStore,
    SafeSearchEnginePort, TunnelingFlagStore,
};
use ferrous_dns_domain::{
    BlockSource, DgaDetectionAction, DgaDetectionConfig, DnsQuery, DnsRequest, DomainError,
    NxdomainHijackAction, NxdomainHijackConfig, QueryLog, QuerySource, RecordType,
    ResponseIpFilterAction, ResponseIpFilterConfig, TunnelingAction, TunnelingDetectionConfig,
};
use lru::LruCache;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

const LAST_SEEN_CAPACITY: usize = 8_192;

thread_local! {
    static LAST_SEEN_TRACKER: RefCell<LruCache<IpAddr, u64>> =
        RefCell::new(LruCache::new(NonZeroUsize::new(LAST_SEEN_CAPACITY).unwrap()));
}

pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    block_filter: Arc<dyn BlockFilterEnginePort>,
    safe_search: Option<Arc<dyn SafeSearchEnginePort>>,
    query_log: Arc<dyn QueryLogRepository>,
    client_repo: Option<Arc<dyn ClientRepository>>,
    client_tracking_interval: Duration,
    rebinding_guard: RebindingGuard,
    rate_limiter: Arc<DnsRateLimiter>,
    tunneling_guard: TunnelingGuard,
    tunneling_event_tx: Option<tokio::sync::mpsc::Sender<TunnelingAnalysisEvent>>,
    tunneling_flag_store: Option<Arc<dyn TunnelingFlagStore>>,
    nxdomain_hijack_guard: NxdomainHijackGuard,
    response_ip_filter_guard: ResponseIpFilterGuard,
    dga_guard: DgaGuard,
    dga_event_tx: Option<tokio::sync::mpsc::Sender<DgaAnalysisEvent>>,
    dga_flag_store: Option<Arc<dyn DgaFlagStore>>,
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
            safe_search: None,
            query_log,
            client_repo: None,
            client_tracking_interval: Duration::from_secs(60),
            rebinding_guard: RebindingGuard::disabled(),
            rate_limiter: Arc::new(DnsRateLimiter::disabled()),
            tunneling_guard: TunnelingGuard::disabled(),
            tunneling_event_tx: None,
            tunneling_flag_store: None,
            nxdomain_hijack_guard: NxdomainHijackGuard::disabled(),
            response_ip_filter_guard: ResponseIpFilterGuard::disabled(),
            dga_guard: DgaGuard::disabled(),
            dga_event_tx: None,
            dga_flag_store: None,
        }
    }

    pub fn with_safe_search(mut self, safe_search: Arc<dyn SafeSearchEnginePort>) -> Self {
        self.safe_search = Some(safe_search);
        self
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

    /// Enables DNS rebinding protection. Resolving a public domain to a private IP
    /// is blocked unless the domain matches `local_domain` suffix, is served by the
    /// local DNS server, or is explicitly listed in `allowlist`.
    pub fn with_rebinding_protection(
        mut self,
        enabled: bool,
        local_domain: Option<&str>,
        allowlist: &[String],
    ) -> Self {
        self.rebinding_guard = RebindingGuard::new(enabled, local_domain, allowlist);
        self
    }

    /// Injects the DNS rate limiter for per-subnet query throttling.
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<DnsRateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    /// Enables phase-1 DNS tunneling detection on the hot path.
    pub fn with_tunneling_detection(mut self, config: &TunnelingDetectionConfig) -> Self {
        self.tunneling_guard = TunnelingGuard::from_config(config);
        self
    }

    /// Injects the sender for emitting analysis events to the background task.
    pub fn with_tunneling_event_sender(
        mut self,
        tx: tokio::sync::mpsc::Sender<TunnelingAnalysisEvent>,
    ) -> Self {
        self.tunneling_event_tx = Some(tx);
        self
    }

    /// Injects the flag store for checking background-flagged domains.
    pub fn with_tunneling_flag_store(mut self, store: Arc<dyn TunnelingFlagStore>) -> Self {
        self.tunneling_flag_store = Some(store);
        self
    }

    /// Enables NXDomain hijack detection on the hot path.
    pub fn with_nxdomain_hijack_detection(
        mut self,
        config: &NxdomainHijackConfig,
        store: Arc<dyn NxdomainHijackIpStore>,
    ) -> Self {
        self.nxdomain_hijack_guard = NxdomainHijackGuard::new(config.action, store);
        self
    }

    /// Enables response IP filtering (C2 IP blocking) on the hot path.
    pub fn with_response_ip_filter(
        mut self,
        config: &ResponseIpFilterConfig,
        store: Arc<dyn ResponseIpFilterStore>,
    ) -> Self {
        self.response_ip_filter_guard = ResponseIpFilterGuard::new(config.action, store);
        self
    }

    /// Enables phase-1 DGA detection on the hot path.
    pub fn with_dga_detection(mut self, config: &DgaDetectionConfig) -> Self {
        self.dga_guard = DgaGuard::from_config(config);
        self
    }

    /// Injects the sender for emitting DGA analysis events to the background task.
    pub fn with_dga_event_sender(
        mut self,
        tx: tokio::sync::mpsc::Sender<DgaAnalysisEvent>,
    ) -> Self {
        self.dga_event_tx = Some(tx);
        self
    }

    /// Injects the flag store for checking background-flagged DGA domains.
    pub fn with_dga_flag_store(mut self, store: Arc<dyn DgaFlagStore>) -> Self {
        self.dga_flag_store = Some(store);
        self
    }

    /// Applies the configured tunneling action, returning an error if blocked.
    fn apply_tunneling_action(
        &self,
        request: &DnsRequest,
        context: &str,
        elapsed_us: u64,
        group_id: i64,
    ) -> Result<(), DomainError> {
        match self.tunneling_guard.action() {
            TunnelingAction::Block => {
                tracing::debug!(domain = %request.domain, context, "DNS tunneling blocked");
                self.log(&QueryLog {
                    blocked: true,
                    response_status: Some("TUNNELING_BLOCKED"),
                    block_source: Some(BlockSource::DnsTunneling),
                    ..Self::base_query_log(request, elapsed_us, group_id)
                });
                Err(DomainError::DnsTunnelingDetected)
            }
            TunnelingAction::Alert => {
                tracing::info!(domain = %request.domain, context, "DNS tunneling alert");
                Ok(())
            }
            TunnelingAction::Throttle => {
                tracing::info!(domain = %request.domain, context, "DNS tunneling alert (throttle mode)");
                Ok(())
            }
        }
    }

    /// Emits a tunneling analysis event to the background task (non-blocking).
    /// Skips emission for whitelisted clients.
    fn emit_tunneling_event(&self, request: &DnsRequest, was_nxdomain: bool) {
        if let Some(ref tx) = self.tunneling_event_tx {
            if self
                .tunneling_guard
                .is_client_whitelisted(request.client_ip)
            {
                return;
            }
            let _ = tx.try_send(TunnelingAnalysisEvent {
                domain: Arc::clone(&request.domain),
                record_type: request.record_type,
                client_ip: request.client_ip,
                was_nxdomain,
            });
        }
    }

    /// Applies the configured DGA action, returning an error if blocked.
    fn apply_dga_action(
        &self,
        request: &DnsRequest,
        context: &str,
        elapsed_us: u64,
        group_id: i64,
    ) -> Result<(), DomainError> {
        match self.dga_guard.action() {
            DgaDetectionAction::Block => {
                tracing::debug!(domain = %request.domain, context, "DGA domain blocked");
                self.log(&QueryLog {
                    blocked: true,
                    response_status: Some("DGA_BLOCKED"),
                    block_source: Some(BlockSource::DgaDetection),
                    ..Self::base_query_log(request, elapsed_us, group_id)
                });
                Err(DomainError::DgaDomainDetected)
            }
            DgaDetectionAction::Alert => {
                tracing::info!(domain = %request.domain, context, "DGA domain alert");
                Ok(())
            }
        }
    }

    /// Emits a DGA analysis event to the background task (non-blocking).
    /// Skips emission for whitelisted clients.
    fn emit_dga_event(&self, request: &DnsRequest) {
        if let Some(ref tx) = self.dga_event_tx {
            if self.dga_guard.is_client_whitelisted(request.client_ip) {
                return;
            }
            let _ = tx.try_send(DgaAnalysisEvent {
                domain: Arc::clone(&request.domain),
                client_ip: request.client_ip,
            });
        }
    }

    fn log(&self, query_log: &QueryLog) {
        if let Err(e) = self.query_log.log_query_sync(query_log) {
            tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log query");
        }
    }

    fn base_query_log(request: &DnsRequest, response_time_us: u64, group_id: i64) -> QueryLog {
        QueryLog {
            id: None,
            domain: Arc::clone(&request.domain),
            record_type: request.record_type,
            client_ip: request.client_ip,
            client_hostname: None,
            blocked: false,
            response_time_us: Some(response_time_us),
            cache_hit: false,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: None,
            upstream_pool: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: Some(group_id),
            block_source: None,
        }
    }

    fn maybe_track_client(&self, client_ip: IpAddr) {
        let Some(client_repo) = &self.client_repo else {
            return;
        };

        let now_ns = coarse_now_ns();
        let interval_ns = self.client_tracking_interval.as_nanos() as u64;
        let needs_update = LAST_SEEN_TRACKER.with(|t| {
            let mut tracker = t.borrow_mut();
            match tracker.peek(&client_ip) {
                Some(&last_ns) if now_ns.saturating_sub(last_ns) < interval_ns => false,
                _ => {
                    tracker.put(client_ip, now_ns);
                    true
                }
            }
        });

        if needs_update {
            let client_repo = Arc::clone(client_repo);
            tokio::spawn(async move {
                if let Err(e) = client_repo.update_last_seen(client_ip).await {
                    tracing::warn!(error = %e, ip = %client_ip, "Failed to track client");
                }
            });
        }
    }

    fn blocked_cname(&self, cname_chain: &[Arc<str>], group_id: i64) -> Option<BlockSource> {
        cname_chain
            .iter()
            .find(|domain| {
                matches!(
                    self.block_filter.check(domain, group_id),
                    FilterDecision::Block(_)
                )
            })
            .map(|_| BlockSource::CnameCloaking)
    }

    /// Checks the cache for a non-IP record type (NS, CNAME, SOA, PTR, MX, TXT,
    /// HTTPS, SRV, SVCB) and returns the raw wire bytes if there is a hit.
    /// The caller is responsible for patching the query ID before sending.
    pub fn try_cache_wire_direct(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> Option<(bytes::Bytes, u32)> {
        let tsc_start = tsc_timer::now();
        let group_id = self.block_filter.resolve_group(client_ip);

        if let FilterDecision::Block(_) = self.block_filter.check(domain, group_id) {
            return None;
        }

        if !self.rate_limiter.is_allowed(client_ip) {
            return None;
        }

        if let Some(ref store) = self.tunneling_flag_store {
            if store.is_flagged(domain) {
                return None;
            }
        }

        if let Some(ref store) = self.dga_flag_store {
            if store.is_flagged(domain) {
                return None;
            }
        }

        let resolution = self.resolver.try_cache_str(domain, record_type)?;
        let wire = resolution.upstream_wire_data?;
        let ttl = resolution.min_ttl.unwrap_or(0);

        let elapsed_us = tsc_timer::elapsed_us_since(tsc_start);
        let domain_arc: Arc<str> = Arc::from(domain);
        self.log(&QueryLog {
            id: None,
            domain: domain_arc,
            record_type,
            client_ip,
            client_hostname: None,
            blocked: false,
            response_time_us: Some(elapsed_us),
            cache_hit: true,
            cache_refresh: false,
            dnssec_status: resolution.dnssec_status,
            upstream_server: None,
            upstream_pool: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: Some(group_id),
            block_source: None,
        });

        Some((wire, ttl))
    }

    pub fn try_cache_direct(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> Option<(Arc<Vec<IpAddr>>, u32)> {
        let tsc_start = tsc_timer::now();
        let group_id = self.block_filter.resolve_group(client_ip);

        if let FilterDecision::Block(_) = self.block_filter.check(domain, group_id) {
            return None;
        }

        if !self.rate_limiter.is_allowed(client_ip) {
            return None;
        }

        if let Some(ref store) = self.tunneling_flag_store {
            if store.is_flagged(domain) {
                return None;
            }
        }

        if let Some(ref store) = self.dga_flag_store {
            if store.is_flagged(domain) {
                return None;
            }
        }

        let resolution = self.resolver.try_cache_str(domain, record_type)?;
        if resolution.addresses.is_empty() {
            return None;
        }
        if self.nxdomain_hijack_guard.is_hijacked_response(&resolution) {
            return None; // fall through to execute() for logging
        }
        if self.response_ip_filter_guard.has_blocked_ip(&resolution) {
            return None; // fall through to execute() for logging
        }

        let elapsed_us = tsc_timer::elapsed_us_since(tsc_start);
        let domain_arc: Arc<str> = Arc::from(domain);
        self.log(&QueryLog {
            id: None,
            domain: domain_arc,
            record_type,
            client_ip,
            client_hostname: None,
            blocked: false,
            response_time_us: Some(elapsed_us),
            cache_hit: true,
            cache_refresh: false,
            dnssec_status: resolution.dnssec_status,
            upstream_server: None,
            upstream_pool: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: Some(group_id),
            block_source: None,
        });

        Some((resolution.addresses, resolution.min_ttl.unwrap_or(60)))
    }

    pub async fn execute(&self, request: &DnsRequest) -> Result<DnsResolution, DomainError> {
        let tsc_start = tsc_timer::now();
        let elapsed_us = || tsc_timer::elapsed_us_since(tsc_start);

        self.maybe_track_client(request.client_ip);

        let group_id = self.block_filter.resolve_group(request.client_ip);

        match self.rate_limiter.check(request.client_ip, false) {
            RateLimitDecision::Allow => {}
            RateLimitDecision::DryRunWouldRefuse => {
                tracing::debug!(client = %request.client_ip, "[dry-run] would rate-limit");
            }
            RateLimitDecision::Refuse => {
                self.log(&QueryLog {
                    blocked: true,
                    response_status: Some("RATE_LIMITED"),
                    block_source: Some(BlockSource::RateLimit),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                return Err(DomainError::DnsRateLimited);
            }
            RateLimitDecision::Slip => {
                self.log(&QueryLog {
                    blocked: true,
                    response_status: Some("RATE_LIMITED_TC"),
                    block_source: Some(BlockSource::RateLimit),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                return Err(DomainError::DnsRateLimitedSlip);
            }
        }

        if let TunnelingVerdict::Detected {
            signal,
            measured,
            threshold,
        } = self
            .tunneling_guard
            .check(&request.domain, request.record_type, request.client_ip)
        {
            tracing::debug!(
                domain = %request.domain,
                signal,
                measured,
                threshold,
                "Tunneling phase-1 signal"
            );
            self.apply_tunneling_action(request, signal, elapsed_us(), group_id)?;
        }

        if let Some(ref store) = self.tunneling_flag_store {
            if store.is_flagged(&request.domain) {
                self.apply_tunneling_action(request, "flagged_domain", elapsed_us(), group_id)?;
            }
        }

        // DGA Detection — Phase 1 (hot-path guard)
        if let DgaVerdict::Detected {
            signal,
            measured,
            threshold,
        } = self.dga_guard.check(&request.domain, request.client_ip)
        {
            tracing::debug!(
                domain = %request.domain,
                signal,
                measured,
                threshold,
                "DGA phase-1 signal"
            );
            self.apply_dga_action(request, signal, elapsed_us(), group_id)?;
        }

        // DGA Detection — Phase 2 (flagged check)
        if let Some(ref store) = self.dga_flag_store {
            if store.is_flagged(&request.domain) {
                self.apply_dga_action(request, "flagged_domain", elapsed_us(), group_id)?;
            }
        }

        let dns_query = DnsQuery::new(Arc::clone(&request.domain), request.record_type);

        if let FilterDecision::Block(block_source) =
            self.block_filter.check(&request.domain, group_id)
        {
            self.log(&QueryLog {
                blocked: true,
                response_status: Some("BLOCKED"),
                block_source: Some(block_source),
                ..Self::base_query_log(request, elapsed_us(), group_id)
            });
            return Err(DomainError::Blocked);
        }

        if let Some(cname_target) = self
            .safe_search
            .as_deref()
            .and_then(|ss| ss.cname_for(&request.domain, group_id))
        {
            let safe_query = DnsQuery::new(Arc::from(cname_target), request.record_type);
            let resolution = self.resolver.resolve(&safe_query).await?;
            self.log(&QueryLog {
                cache_hit: resolution.cache_hit,
                upstream_server: resolution.upstream_server.clone(),
                upstream_pool: resolution.upstream_pool.clone(),
                response_status: Some("SAFE_SEARCH"),
                ..Self::base_query_log(request, elapsed_us(), group_id)
            });
            return Ok(resolution);
        }

        if let Some(cached) = self.resolver.try_cache(&dns_query) {
            if cached.has_response_data() {
                if self.nxdomain_hijack_guard.is_hijacked_response(&cached)
                    || self.response_ip_filter_guard.has_blocked_ip(&cached)
                {
                    // Fall through to full resolve path for logging and action.
                } else {
                    self.log(&QueryLog {
                        cache_hit: true,
                        dnssec_status: cached.dnssec_status,
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Ok(cached);
                }
            } else if cached.cache_hit {
                self.log(&QueryLog {
                    cache_hit: true,
                    response_status: Some("NXDOMAIN"),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                return Err(DomainError::NxDomain);
            }
        }

        match self.resolver.resolve(&dns_query).await {
            Ok(resolution) => {
                if let Some(block_source) = self.blocked_cname(&resolution.cname_chain, group_id) {
                    let ttl = resolution.min_ttl.map(|t| t as u64).unwrap_or(60).max(5);
                    self.block_filter
                        .store_cname_decision(&request.domain, group_id, ttl);
                    self.log(&QueryLog {
                        blocked: true,
                        response_status: Some("BLOCKED"),
                        block_source: Some(block_source),
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Err(DomainError::Blocked);
                }
                if self
                    .rebinding_guard
                    .is_rebinding_attempt(&request.domain, &resolution)
                {
                    self.log(&QueryLog {
                        blocked: true,
                        response_status: Some("BLOCKED"),
                        block_source: Some(BlockSource::DnsRebinding),
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Err(DomainError::Blocked);
                }
                if self.nxdomain_hijack_guard.is_hijacked_response(&resolution) {
                    match self.nxdomain_hijack_guard.action() {
                        NxdomainHijackAction::Block => {
                            self.log(&QueryLog {
                                blocked: true,
                                response_status: Some("NXDOMAIN_HIJACK"),
                                block_source: Some(BlockSource::NxdomainHijack),
                                ..Self::base_query_log(request, elapsed_us(), group_id)
                            });
                            return Err(DomainError::NxDomain);
                        }
                        NxdomainHijackAction::Alert => {
                            tracing::info!(
                                domain = %request.domain,
                                "NXDomain hijack detected (alert mode)"
                            );
                        }
                    }
                }
                if self.response_ip_filter_guard.has_blocked_ip(&resolution) {
                    match self.response_ip_filter_guard.action() {
                        ResponseIpFilterAction::Block => {
                            self.log(&QueryLog {
                                blocked: true,
                                response_status: Some("RESPONSE_IP_BLOCKED"),
                                block_source: Some(BlockSource::ResponseIpFilter),
                                ..Self::base_query_log(request, elapsed_us(), group_id)
                            });
                            return Err(DomainError::Blocked);
                        }
                        ResponseIpFilterAction::Alert => {
                            tracing::info!(
                                domain = %request.domain,
                                "Response IP filter: C2 IP detected (alert mode)"
                            );
                        }
                    }
                }
                let response_status = if resolution.local_dns {
                    Some("LOCAL_DNS")
                } else {
                    Some("NOERROR")
                };
                self.emit_tunneling_event(request, false);
                self.emit_dga_event(request);
                self.log(&QueryLog {
                    cache_hit: resolution.cache_hit,
                    dnssec_status: resolution.dnssec_status,
                    upstream_server: resolution.upstream_server.clone(),
                    upstream_pool: resolution.upstream_pool.clone(),
                    response_status,
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Ok(resolution)
            }
            Err(DomainError::LocalNxDomain) => {
                self.log(&QueryLog {
                    response_status: Some("LOCAL_DNS"),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Err(DomainError::NxDomain)
            }
            Err(e) => {
                let response_status = match &e {
                    DomainError::NxDomain => {
                        self.emit_tunneling_event(request, true);
                        self.emit_dga_event(request);
                        "NXDOMAIN"
                    }
                    DomainError::QueryTimeout => "TIMEOUT",
                    _ => "SERVFAIL",
                };
                self.log(&QueryLog {
                    response_status: Some(response_status),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Err(e)
            }
        }
    }
}
