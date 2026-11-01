use super::coarse_timer::coarse_now_ns;
use super::cookie_guard::DnsCookieGuard;
use super::dga_guard::{DgaAnalysisEvent, DgaGuard, DgaVerdict};
use super::nxdomain_hijack_guard::NxdomainHijackGuard;
use super::rate_limiter::{DnsRateLimiter, RateLimitDecision};
use super::rebinding_guard::RebindingGuard;
use super::response_ip_filter_guard::ResponseIpFilterGuard;
use super::tsc_timer;
use super::tunneling_guard::{TunnelingAnalysisEvent, TunnelingGuard, TunnelingVerdict};
use super::upstream_admission::UpstreamAdmission;
use crate::drop_counter::DropCounter;
use crate::ports::{
    BlockFilterEnginePort, ClientRepository, DgaFlagStore, DnsResolution, DnsResolver,
    FilterDecision, MalwareExemptionPort, NxdomainHijackIpStore, QueryLogRepository,
    ResponseIpFilterStore, SafeSearchEnginePort, TunnelingFlagStore,
};
use ferrous_dns_domain::{
    BlockSource, ClientProtocol, DgaDetectionAction, DgaDetectionConfig, DnsQuery, DnsRequest,
    DnssecStatus, DomainError, Nat64Prefix, NxdomainHijackAction, NxdomainHijackConfig, QueryLog,
    QuerySource, RecordType, ResponseIpFilterAction, ResponseIpFilterConfig, TunnelingAction,
    TunnelingDetectionConfig,
};
use lru::LruCache;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::SemaphorePermit;

const LAST_SEEN_CAPACITY: NonZeroUsize = match NonZeroUsize::new(8_192) {
    Some(n) => n,
    None => NonZeroUsize::MIN,
};

thread_local! {
    static LAST_SEEN_TRACKER: RefCell<LruCache<IpAddr, u64>> =
        RefCell::new(LruCache::new(LAST_SEEN_CAPACITY));
}

/// What the operator's rules leave a query to be checked against.
#[derive(Clone, Copy)]
struct Screening {
    group_id: i64,
    /// The answer's CNAME chain goes through the block filter (CNAME cloaking).
    cloaking: bool,
    /// The malware detectors run. An explicit allow lifts them, since clearing
    /// their false positives is what the allowlist is for, and so does a group
    /// with Malware Detection switched off.
    detectors: bool,
}

/// A detector that judged the query by its name alone, with the signal it
/// fired on.
enum NameHit {
    Tunneling(&'static str),
    Dga(&'static str),
}

pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    block_filter: Arc<dyn BlockFilterEnginePort>,
    safe_search: Option<Arc<dyn SafeSearchEnginePort>>,
    query_log: Arc<dyn QueryLogRepository>,
    client_repo: Option<Arc<dyn ClientRepository>>,
    client_tracking_interval: Duration,
    rebinding_guard: Option<RebindingGuard>,
    rate_limiter: Arc<DnsRateLimiter>,
    tunneling_guard: TunnelingGuard,
    tunneling_event_tx: Option<tokio::sync::mpsc::Sender<TunnelingAnalysisEvent>>,
    tunneling_flag_store: Option<Arc<dyn TunnelingFlagStore>>,
    nxdomain_hijack_guard: NxdomainHijackGuard,
    response_ip_filter_guard: ResponseIpFilterGuard,
    dga_guard: DgaGuard,
    dga_event_tx: Option<tokio::sync::mpsc::Sender<DgaAnalysisEvent>>,
    dga_flag_store: Option<Arc<dyn DgaFlagStore>>,
    malware_exemptions: Option<Arc<dyn MalwareExemptionPort>>,
    cookie_guard: Option<DnsCookieGuard>,
    upstream_admission: Option<UpstreamAdmission>,
    dnssec_enforce: bool,
    dns64_prefix: Option<Ipv6Addr>,
    log_queries: bool,
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
            rebinding_guard: None,
            rate_limiter: Arc::new(DnsRateLimiter::disabled()),
            tunneling_guard: TunnelingGuard::disabled(),
            tunneling_event_tx: None,
            tunneling_flag_store: None,
            nxdomain_hijack_guard: NxdomainHijackGuard::disabled(),
            response_ip_filter_guard: ResponseIpFilterGuard::disabled(),
            dga_guard: DgaGuard::disabled(),
            dga_event_tx: None,
            dga_flag_store: None,
            malware_exemptions: None,
            cookie_guard: None,
            upstream_admission: None,
            dnssec_enforce: false,
            dns64_prefix: None,
            log_queries: true,
        }
    }

    /// Enables DNSSEC enforcement (Strict mode): a `Bogus` validation result
    /// returns SERVFAIL to the client, unless the client set the CD bit.
    pub fn with_dnssec_enforcement(mut self, enforce: bool) -> Self {
        self.dnssec_enforce = enforce;
        self
    }

    /// Honors `[database] log_queries`. When `false`, every query-log write is
    /// suppressed and the hot cache-hit path skips building the log entry
    /// entirely. Defaults to `true` (log all queries).
    pub fn with_query_logging(mut self, enabled: bool) -> Self {
        self.log_queries = enabled;
        self
    }

    /// Records the `/96` NAT64 prefix so AAAA answers synthesized by the DNS64
    /// resolver layer can be tagged in the query log. Only used for the tag.
    pub fn with_dns64(mut self, prefix: Ipv6Addr) -> Self {
        self.dns64_prefix = Some(prefix);
        self
    }

    /// Whether an AAAA answer was synthesized by DNS64: every answer address
    /// falls inside the configured NAT64 prefix (RFC 6052 reserves `64:ff9b::/96`
    /// exclusively for NAT64, so a real AAAA never lands there).
    fn is_dns64_synthesized(&self, record_type: RecordType, addresses: &[IpAddr]) -> bool {
        record_type == RecordType::AAAA
            && self.dns64_prefix.is_some_and(|prefix| {
                !addresses.is_empty()
                    && addresses.iter().all(|addr| match addr {
                        IpAddr::V6(v6) => Nat64Prefix::contains(prefix, *v6),
                        IpAddr::V4(_) => false,
                    })
            })
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
        local_domain: Option<&str>,
        allowlist: &[String],
    ) -> Self {
        self.rebinding_guard = Some(RebindingGuard::new(local_domain, allowlist));
        self
    }

    /// Injects the DNS rate limiter for per-subnet query throttling.
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<DnsRateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    /// Bounds the queries waiting on an upstream at once, over every transport:
    /// past `limit`, a query that would go upstream fails with
    /// `UpstreamCapacityExhausted` instead of waiting, and counts in `shed`.
    /// Unbounded by default.
    pub fn with_upstream_limit(mut self, limit: usize, shed: Arc<DropCounter>) -> Self {
        self.upstream_admission = Some(UpstreamAdmission::new(limit, shed));
        self
    }

    /// A slot for a query about to wait on an upstream, held until it drops.
    fn admit_upstream(&self) -> Result<Option<SemaphorePermit<'_>>, DomainError> {
        self.upstream_admission
            .as_ref()
            .map(UpstreamAdmission::try_admit)
            .transpose()
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

    /// Skips the malware detectors for the clients of a group with Malware
    /// Detection switched off.
    pub fn with_malware_exemptions(mut self, exemptions: Arc<dyn MalwareExemptionPort>) -> Self {
        self.malware_exemptions = Some(exemptions);
        self
    }

    /// Enables RFC 7873 DNS Cookie validation on the hot path.
    pub fn with_dns_cookies(mut self, guard: DnsCookieGuard) -> Self {
        self.cookie_guard = Some(guard);
        self
    }

    /// The cookie guard the server handler signs response cookies with;
    /// `None` when DNS Cookies are disabled.
    pub fn cookie_guard(&self) -> Option<&DnsCookieGuard> {
        self.cookie_guard.as_ref()
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
            action @ (TunnelingAction::Alert | TunnelingAction::Throttle) => {
                tracing::info!(domain = %request.domain, context, ?action, "DNS tunneling alert");
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
        if !self.log_queries {
            return;
        }
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
            dns64_synthesized: false,
            answers: None,
            upstream_server: None,
            upstream_pool: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            protocol: request.protocol,
            group_id: Some(group_id),
            block_source: None,
            coalesced: None,
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

    fn is_cname_cloaked(&self, cname_chain: &[Arc<str>], group_id: i64) -> bool {
        cname_chain.iter().any(|domain| {
            matches!(
                self.block_filter.check(domain, group_id),
                FilterDecision::Block(_)
            )
        })
    }

    #[inline]
    fn screening(&self, group_id: i64, filter_decision: FilterDecision) -> Screening {
        let explicitly_allowed = matches!(filter_decision, FilterDecision::ExplicitAllow);
        Screening {
            group_id,
            cloaking: !explicitly_allowed,
            detectors: !explicitly_allowed
                && !self
                    .malware_exemptions
                    .as_ref()
                    .is_some_and(|exemptions| exemptions.is_exempt(group_id)),
        }
    }

    /// Runs the detectors that judge a query by its name alone, each phase-1
    /// check before its phase-2 flag, and hands every hit to `on_hit` in that
    /// order. Both paths share this one list: [`Self::execute`] applies each
    /// hit's action, while a cache probe gives up at the first one.
    #[inline]
    fn screen_name<B>(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        mut on_hit: impl FnMut(NameHit) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        if let TunnelingVerdict::Detected {
            signal,
            measured,
            threshold,
        } = self.tunneling_guard.check(domain, record_type, client_ip)
        {
            tracing::debug!(
                domain,
                signal,
                measured,
                threshold,
                "Tunneling phase-1 signal"
            );
            on_hit(NameHit::Tunneling(signal))?;
        }
        if self
            .tunneling_flag_store
            .as_ref()
            .is_some_and(|store| store.is_flagged(domain))
        {
            on_hit(NameHit::Tunneling("flagged_domain"))?;
        }
        if let DgaVerdict::Detected {
            signal,
            measured,
            threshold,
        } = self.dga_guard.check(domain, client_ip)
        {
            tracing::debug!(domain, signal, measured, threshold, "DGA phase-1 signal");
            on_hit(NameHit::Dga(signal))?;
        }
        if self
            .dga_flag_store
            .as_ref()
            .is_some_and(|store| store.is_flagged(domain))
        {
            on_hit(NameHit::Dga("flagged_domain"))?;
        }
        ControlFlow::Continue(())
    }

    /// Fast-path admission shared by both cache probes: `None` means fall
    /// through to [`Self::execute`], which logs the query and applies whatever
    /// stopped it here.
    #[inline]
    fn cache_gate(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> Option<Screening> {
        // Strict DNS Cookies validate every UDP query, which `execute` does.
        if self
            .cookie_guard
            .as_ref()
            .is_some_and(DnsCookieGuard::is_strict)
        {
            return None;
        }

        let group_id = self.block_filter.resolve_group(client_ip);

        let filter_decision = self.block_filter.check(domain, group_id);
        if let FilterDecision::Block(_) = filter_decision {
            return None;
        }

        if !self.rate_limiter.is_allowed(client_ip) {
            return None;
        }

        let screening = self.screening(group_id, filter_decision);
        // The cache is shared across groups, so a name another client resolved
        // is checked here exactly as on a miss.
        if screening.detectors
            && self
                .screen_name(domain, record_type, client_ip, |_| ControlFlow::Break(()))
                .is_break()
        {
            return None;
        }

        Some(screening)
    }

    fn cache_hit_log(
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        protocol: ClientProtocol,
        group_id: i64,
        elapsed_us: u64,
        dnssec_status: Option<DnssecStatus>,
    ) -> QueryLog {
        QueryLog {
            id: None,
            domain: Arc::from(domain),
            record_type,
            client_ip,
            client_hostname: None,
            blocked: false,
            response_time_us: Some(elapsed_us),
            cache_hit: true,
            cache_refresh: false,
            dnssec_status,
            dns64_synthesized: false,
            answers: None,
            upstream_server: None,
            upstream_pool: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            protocol: Some(protocol),
            group_id: Some(group_id),
            block_source: None,
            coalesced: None,
        }
    }

    /// Checks the cache for a non-IP record type (NS, CNAME, SOA, PTR, MX, TXT,
    /// HTTPS, SRV, SVCB) and hands a hit's wire bytes and the seconds its entry
    /// has left to `respond`, which builds the reply or declines it (`None`)
    /// for the slow path. Only a hit `respond` answers is logged here;
    /// [`Self::execute`] logs a declined one.
    pub fn try_cache_wire_direct<R>(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        protocol: ClientProtocol,
        respond: impl FnOnce(&[u8], u32) -> Option<R>,
    ) -> Option<R> {
        let tsc_start = tsc_timer::now();
        let screening = self.cache_gate(domain, record_type, client_ip)?;
        let group_id = screening.group_id;

        let resolution = self
            .resolver
            .try_cache_str(domain, record_type, Some(group_id))?;
        // Only `execute` can charge the NXDOMAIN budget.
        if Self::spends_nxdomain_budget(&resolution) && self.rate_limiter.limits_nxdomain() {
            return None;
        }
        // Fall through to execute() so it logs and blocks it.
        if screening.cloaking && self.is_cname_cloaked(&resolution.cname_chain, group_id) {
            return None;
        }
        let wire = resolution.upstream_wire_data.as_deref()?;
        // The cache reports what every entry has left; the reply's TTLs need it.
        let remaining = resolution.min_ttl?;
        // Built before `respond`, which rarely declines, and logged only once
        // it answers: the slow path logs a declined hit. The logged time is
        // the cache probe's.
        let log = self.log_queries.then(|| QueryLog {
            response_status: Some(resolution.rcode_name()),
            ..Self::cache_hit_log(
                domain,
                record_type,
                client_ip,
                protocol,
                group_id,
                tsc_timer::elapsed_us_since(tsc_start),
                resolution.dnssec_status,
            )
        });
        let reply = respond(wire, remaining)?;
        if let Some(log) = &log {
            self.log(log);
        }

        Some(reply)
    }

    /// Checks the cache for an A/AAAA answer and hands its addresses and TTL
    /// to `respond`, logging the hit only if `respond` answers it; see
    /// [`Self::try_cache_wire_direct`].
    pub fn try_cache_direct<R>(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        protocol: ClientProtocol,
        respond: impl FnOnce(&[IpAddr], u32) -> Option<R>,
    ) -> Option<R> {
        let tsc_start = tsc_timer::now();
        let screening = self.cache_gate(domain, record_type, client_ip)?;
        let group_id = screening.group_id;

        let resolution = self
            .resolver
            .try_cache_str(domain, record_type, Some(group_id))?;
        if resolution.addresses.is_empty() {
            return None;
        }
        // Fall through to execute() so it logs and applies the configured action.
        if (screening.cloaking && self.is_cname_cloaked(&resolution.cname_chain, group_id))
            || (screening.detectors && self.is_suspicious_cached_answer(domain, &resolution))
        {
            return None;
        }
        let DnsResolution {
            addresses,
            min_ttl,
            dnssec_status,
            ..
        } = resolution;
        // Built before `respond`, which rarely declines, and logged only once
        // it answers: the slow path logs a declined hit.
        let log = self.log_queries.then(|| QueryLog {
            dns64_synthesized: self.is_dns64_synthesized(record_type, &addresses),
            answers: Some(Arc::clone(&addresses)),
            ..Self::cache_hit_log(
                domain,
                record_type,
                client_ip,
                protocol,
                group_id,
                tsc_timer::elapsed_us_since(tsc_start),
                dnssec_status,
            )
        });
        let reply = respond(&addresses, min_ttl.unwrap_or(60))?;
        if let Some(log) = &log {
            self.log(log);
        }

        Some(reply)
    }

    /// Cached answers are admitted before the response guards run, so re-check the
    /// ones whose verdict depends on the answer (hijack, C2 IP, rebinding).
    /// CNAME cloaking is checked on its own, because a cached hit can be blocked
    /// without the upstream path.
    #[inline]
    fn is_suspicious_cached_answer(&self, domain: &str, resolution: &DnsResolution) -> bool {
        self.nxdomain_hijack_guard.is_hijacked_response(resolution)
            || self.response_ip_filter_guard.has_blocked_ip(resolution)
            || self.is_rebinding_attempt(domain, resolution)
    }

    /// Blocks `request` for an answer whose CNAME chain goes through a blocked
    /// name, and remembers the verdict for the chain's TTL so the next query is
    /// refused before any lookup.
    fn block_cname_cloaking(
        &self,
        request: &DnsRequest,
        resolution: &DnsResolution,
        group_id: i64,
        response_time_us: u64,
    ) -> DomainError {
        let ttl = resolution.min_ttl.map(|t| t as u64).unwrap_or(60).max(5);
        self.block_filter
            .store_cname_decision(&request.domain, group_id, ttl);
        self.log(&QueryLog {
            blocked: true,
            response_status: Some("BLOCKED"),
            block_source: Some(BlockSource::CnameCloaking),
            ..Self::base_query_log(request, response_time_us, group_id)
        });
        DomainError::Blocked
    }

    #[inline]
    fn is_rebinding_attempt(&self, domain: &str, resolution: &DnsResolution) -> bool {
        self.rebinding_guard
            .as_ref()
            .is_some_and(|guard| guard.is_rebinding_attempt(domain, resolution))
    }

    /// Applies a rate-limit decision for `budget`: `Err` carries the configured
    /// action for a response over it, which is logged here.
    fn apply_rate_limit(
        &self,
        decision: RateLimitDecision,
        budget: &'static str,
        request: &DnsRequest,
        elapsed_us: impl Fn() -> u64,
        group_id: i64,
    ) -> Result<(), DomainError> {
        let (status, error) = match decision {
            RateLimitDecision::Allow => return Ok(()),
            RateLimitDecision::DryRunWouldRefuse => {
                tracing::debug!(client = %request.client_ip, budget, "[dry-run] would rate-limit");
                return Ok(());
            }
            RateLimitDecision::Refuse => ("RATE_LIMITED", DomainError::DnsRateLimited),
            RateLimitDecision::Slip => ("RATE_LIMITED_TC", DomainError::DnsRateLimitedSlip),
        };
        self.log(&QueryLog {
            blocked: true,
            response_status: Some(status),
            block_source: Some(BlockSource::RateLimit),
            ..Self::base_query_log(request, elapsed_us(), group_id)
        });
        Err(error)
    }

    /// Charges an NXDOMAIN answer to the client's NXDOMAIN budget; `Err` when
    /// this answer is over it. Callers skip answers from the local DNS server
    /// and internal pools.
    fn charge_nxdomain(
        &self,
        request: &DnsRequest,
        elapsed_us: impl Fn() -> u64,
        group_id: i64,
    ) -> Result<(), DomainError> {
        self.apply_rate_limit(
            self.rate_limiter
                .charge_nxdomain(request.client_ip, request.protocol),
            "nxdomain",
            request,
            elapsed_us,
            group_id,
        )
    }

    /// An upstream's NXDOMAIN, relayed as the upstream's own message. An
    /// internal pool's answers carry `local_dns` and, like the local DNS
    /// server's, never spend the budget.
    #[inline]
    fn spends_nxdomain_budget(resolution: &DnsResolution) -> bool {
        resolution.upstream_nxdomain && !resolution.local_dns
    }

    pub async fn execute(&self, request: &DnsRequest) -> Result<DnsResolution, DomainError> {
        let tsc_start = tsc_timer::now();
        let elapsed_us = || tsc_timer::elapsed_us_since(tsc_start);

        self.maybe_track_client(request.client_ip);

        let group_id = self.block_filter.resolve_group(request.client_ip);

        self.apply_rate_limit(
            self.rate_limiter.check(request.client_ip, request.protocol),
            "queries",
            request,
            elapsed_us,
            group_id,
        )?;

        if let Some(guard) = self
            .cookie_guard
            .as_ref()
            .filter(|g| g.requires_cookie(request.protocol))
        {
            let opt = request
                .edns_cookie
                .as_ref()
                .map(|c| c.as_bytes())
                .unwrap_or(&[]);
            if !guard.has_valid_cookie(request.client_ip, opt) {
                tracing::debug!(
                    domain = %request.domain,
                    client = %request.client_ip,
                    "DNS cookie validation failed (strict mode)"
                );
                return Err(DomainError::DnsCookieInvalid);
            }
        }

        // The filter runs ahead of the heuristic detectors for two reasons: an
        // explicit allow has to be able to clear their false positives, and a
        // domain that is both blocklisted and DGA-shaped should be attributed to
        // the list that names it rather than to the heuristic.
        let filter_decision = self.block_filter.check(&request.domain, group_id);
        if let FilterDecision::Block(block_source) = filter_decision {
            self.log(&QueryLog {
                blocked: true,
                response_status: Some("BLOCKED"),
                block_source: Some(block_source),
                ..Self::base_query_log(request, elapsed_us(), group_id)
            });
            return Err(DomainError::Blocked);
        }
        let screening = self.screening(group_id, filter_decision);

        if screening.detectors {
            let hits = self.screen_name(
                &request.domain,
                request.record_type,
                request.client_ip,
                |hit| {
                    let applied = match hit {
                        NameHit::Tunneling(signal) => {
                            self.apply_tunneling_action(request, signal, elapsed_us(), group_id)
                        }
                        NameHit::Dga(signal) => {
                            self.apply_dga_action(request, signal, elapsed_us(), group_id)
                        }
                    };
                    match applied {
                        Ok(()) => ControlFlow::Continue(()),
                        Err(blocked) => ControlFlow::Break(blocked),
                    }
                },
            );
            if let ControlFlow::Break(blocked) = hits {
                return Err(blocked);
            }
        }

        let dns_query = DnsQuery::new(Arc::clone(&request.domain), request.record_type)
            .with_group(Some(group_id));

        if let Some(cname_target) = self
            .safe_search
            .as_deref()
            .and_then(|ss| ss.cname_for(&request.domain, group_id))
        {
            let safe_query = DnsQuery::new(Arc::from(cname_target), request.record_type)
                .with_group(Some(group_id));
            // `resolve` expects the caller to have probed the cache already.
            let resolution = match self.resolver.try_cache(&safe_query) {
                Some(cached) if cached.has_response_data() => cached,
                _ => {
                    let _upstream_slot = self.admit_upstream()?;
                    self.resolver.resolve(&safe_query).await?
                }
            };
            self.log(&QueryLog {
                cache_hit: resolution.cache_hit,
                upstream_server: resolution.upstream_server.clone(),
                upstream_pool: resolution.upstream_pool.clone(),
                coalesced: resolution.coalesced,
                response_status: Some("SAFE_SEARCH"),
                ..Self::base_query_log(request, elapsed_us(), group_id)
            });
            return Ok(resolution);
        }

        if let Some(cached) = self.resolver.try_cache(&dns_query) {
            if cached.has_response_data() {
                if screening.cloaking && self.is_cname_cloaked(&cached.cname_chain, group_id) {
                    return Err(self.block_cname_cloaking(
                        request,
                        &cached,
                        group_id,
                        elapsed_us(),
                    ));
                }
                if screening.detectors && self.is_suspicious_cached_answer(&request.domain, &cached)
                {
                    // Fall through to full resolve path for logging and action.
                } else {
                    if Self::spends_nxdomain_budget(&cached) {
                        self.charge_nxdomain(request, elapsed_us, group_id)?;
                    }
                    self.log(&QueryLog {
                        cache_hit: true,
                        dnssec_status: cached.dnssec_status,
                        answers: Some(Arc::clone(&cached.addresses)),
                        response_status: Some(cached.rcode_name()),
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Ok(cached);
                }
            } else if cached.cache_hit {
                if !cached.local_nxdomain {
                    self.charge_nxdomain(request, elapsed_us, group_id)?;
                }
                self.log(&QueryLog {
                    cache_hit: true,
                    response_status: Some("NXDOMAIN"),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                return Err(DomainError::NxDomain);
            }
        }

        // Blocked, refused and cached answers above never take a slot.
        let _upstream_slot = self.admit_upstream()?;
        match self.resolver.resolve(&dns_query).await {
            Ok(resolution) => {
                if screening.cloaking && self.is_cname_cloaked(&resolution.cname_chain, group_id) {
                    return Err(self.block_cname_cloaking(
                        request,
                        &resolution,
                        group_id,
                        elapsed_us(),
                    ));
                }
                if screening.detectors && self.is_rebinding_attempt(&request.domain, &resolution) {
                    self.log(&QueryLog {
                        blocked: true,
                        response_status: Some("BLOCKED"),
                        block_source: Some(BlockSource::DnsRebinding),
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Err(DomainError::Blocked);
                }
                if screening.detectors
                    && self.nxdomain_hijack_guard.is_hijacked_response(&resolution)
                {
                    match self.nxdomain_hijack_guard.action() {
                        NxdomainHijackAction::Block => {
                            self.charge_nxdomain(request, elapsed_us, group_id)?;
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
                if screening.detectors && self.response_ip_filter_guard.has_blocked_ip(&resolution)
                {
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
                // DNSSEC enforcement (Strict mode): an answer validation could not
                // establish as Secure or provably Insecure is SERVFAIL — unless the
                // client set the CD bit and so does its own validation. Serving
                // Indeterminate would let anyone who can drop DS/DNSKEY lookups
                // switch validation off.
                let refusal = match resolution.dnssec_status {
                    _ if !self.dnssec_enforce || request.checking_disabled => None,
                    Some(DnssecStatus::Bogus) => Some(("SERVFAIL_BOGUS", DomainError::DnssecBogus)),
                    Some(DnssecStatus::Indeterminate) => {
                        Some(("SERVFAIL_INDETERMINATE", DomainError::DnssecIndeterminate))
                    }
                    Some(DnssecStatus::Secure | DnssecStatus::Insecure) | None => None,
                };
                if let Some((response_status, error)) = refusal {
                    self.log(&QueryLog {
                        dnssec_status: resolution.dnssec_status,
                        response_status: Some(response_status),
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Err(error);
                }
                let response_status = if resolution.local_dns {
                    Some("LOCAL_DNS")
                } else {
                    Some(resolution.rcode_name())
                };
                // An internal pool's NXDOMAIN is the LAN's own: it feeds neither
                // the tunneling ratio nor the NXDOMAIN budget.
                let upstream_nxdomain = Self::spends_nxdomain_budget(&resolution);
                if screening.detectors {
                    self.emit_tunneling_event(request, upstream_nxdomain);
                    self.emit_dga_event(request);
                }
                if upstream_nxdomain {
                    self.charge_nxdomain(request, elapsed_us, group_id)?;
                }
                self.log(&QueryLog {
                    cache_hit: resolution.cache_hit,
                    dnssec_status: resolution.dnssec_status,
                    dns64_synthesized: self
                        .is_dns64_synthesized(request.record_type, &resolution.addresses),
                    answers: Some(Arc::clone(&resolution.addresses)),
                    upstream_server: resolution.upstream_server.clone(),
                    upstream_pool: resolution.upstream_pool.clone(),
                    coalesced: resolution.coalesced,
                    response_status,
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Ok(resolution)
            }
            Err(DomainError::LocalNxDomain) => {
                // LAN traffic, like a PTR sweep: never charged to the NXDOMAIN budget.
                self.log(&QueryLog {
                    response_status: Some("LOCAL_DNS"),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Err(DomainError::NxDomain)
            }
            Err(DomainError::FilteredQuery(block_source)) => {
                // The server answers it with the block response, so the log
                // records a block rather than a SERVFAIL the client never saw.
                self.log(&QueryLog {
                    blocked: true,
                    response_status: Some("BLOCKED"),
                    block_source: Some(block_source),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Err(DomainError::FilteredQuery(block_source))
            }
            Err(e) => {
                let response_status = match &e {
                    DomainError::NxDomain => {
                        if screening.detectors {
                            self.emit_tunneling_event(request, true);
                            self.emit_dga_event(request);
                        }
                        self.charge_nxdomain(request, elapsed_us, group_id)?;
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
