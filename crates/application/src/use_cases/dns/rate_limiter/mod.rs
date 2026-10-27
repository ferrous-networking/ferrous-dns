mod subnet_key;
mod token_bucket;
mod whitelist_set;

use super::coarse_timer::coarse_now_ns;
use dashmap::DashMap;
use ferrous_dns_domain::RateLimitConfig;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use subnet_key::{SubnetGrouping, SubnetKey};
use token_bucket::TokenBucket;
use whitelist_set::WhitelistSet;

/// Outcome of a rate-limit check on the DNS hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Query is within budget — proceed normally.
    Allow,
    /// Query exceeds budget — return REFUSED.
    Refuse,
    /// Query exceeds budget — return TC=1 (truncated) to force TCP retry.
    Slip,
    /// Dry-run mode: would have refused, but the query is allowed.
    DryRunWouldRefuse,
}

/// Token-bucket rate limiter keyed by client subnet.
///
/// Designed for the DNS hot path: zero heap allocation per check, atomic-only
/// state, `DashMap` with `FxBuildHasher` for sharded concurrent access.
pub struct DnsRateLimiter {
    enabled: bool,
    dry_run: bool,
    qps: u32,
    burst: u32,
    nx_qps: u32,
    grouping: SubnetGrouping,
    slip_ratio: u32,
    stale_ttl_ns: u64,
    whitelist: WhitelistSet,
    buckets: Arc<DashMap<SubnetKey, TokenBucket, FxBuildHasher>>,
    slip_counter: AtomicU64,
}

impl DnsRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            enabled: config.enabled,
            dry_run: config.dry_run,
            qps: config.queries_per_second,
            burst: config.burst_size,
            nx_qps: config.nxdomain_per_second,
            grouping: SubnetGrouping::new(config.ipv4_prefix_len, config.ipv6_prefix_len),
            slip_ratio: config.slip_ratio,
            stale_ttl_ns: config.stale_entry_ttl_secs.saturating_mul(1_000_000_000),
            whitelist: WhitelistSet::from_cidrs(&config.whitelist),
            buckets: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            slip_counter: AtomicU64::new(0),
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            dry_run: false,
            qps: 0,
            burst: 0,
            nx_qps: 0,
            grouping: SubnetGrouping::new(24, 56),
            slip_ratio: 0,
            stale_ttl_ns: 0,
            whitelist: WhitelistSet::from_cidrs(&[]),
            buckets: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            slip_counter: AtomicU64::new(0),
        }
    }

    /// Checks whether a query from `client_ip` should be allowed under the
    /// subnet's general budget.
    ///
    /// This is called on the DNS hot path — zero allocations, atomic-only state.
    #[inline]
    pub fn check(&self, client_ip: IpAddr) -> RateLimitDecision {
        if !self.enabled {
            return RateLimitDecision::Allow;
        }
        if self.whitelist.contains(client_ip) {
            return RateLimitDecision::Allow;
        }

        let now_ns = coarse_now_ns();
        let key = self.grouping.key(client_ip);

        let allowed = self
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.burst, self.nx_qps, now_ns))
            .try_consume(now_ns, self.qps, self.burst, self.nx_qps);

        if allowed {
            RateLimitDecision::Allow
        } else {
            self.over_budget()
        }
    }

    /// Charges an NXDOMAIN answer for `client_ip` against its subnet's
    /// NXDOMAIN budget (BIND RRL `nxdomains-per-second`) and decides that
    /// answer: only an NXDOMAIN over budget gets the configured action, and
    /// the subnet's other queries are never limited by it.
    pub fn charge_nxdomain(&self, client_ip: IpAddr) -> RateLimitDecision {
        if !self.limits_nxdomain() {
            return RateLimitDecision::Allow;
        }
        if self.whitelist.contains(client_ip) {
            return RateLimitDecision::Allow;
        }

        let now_ns = coarse_now_ns();
        let key = self.grouping.key(client_ip);
        let covered = self
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.burst, self.nx_qps, now_ns))
            .try_charge_nxdomain(now_ns, self.qps, self.burst, self.nx_qps);

        if covered {
            RateLimitDecision::Allow
        } else {
            self.over_budget()
        }
    }

    /// Whether NXDOMAIN answers are charged at all.
    #[inline]
    pub fn limits_nxdomain(&self) -> bool {
        self.enabled && self.nx_qps > 0
    }

    /// The configured action for a response over one of the budgets.
    fn over_budget(&self) -> RateLimitDecision {
        if self.dry_run {
            return RateLimitDecision::DryRunWouldRefuse;
        }

        if self.slip_ratio > 0 {
            let count = self.slip_counter.fetch_add(1, Ordering::Relaxed);
            if count.is_multiple_of(self.slip_ratio as u64) {
                return RateLimitDecision::Slip;
            }
        }

        RateLimitDecision::Refuse
    }

    /// Lightweight check for the cache fast path: returns `true` if the client
    /// is not currently rate-limited, without consuming a token or creating a bucket.
    /// The authoritative `check()` runs later in `execute()`.
    #[inline]
    pub fn is_allowed(&self, client_ip: IpAddr) -> bool {
        !self.enabled || self.is_allowed_enabled(client_ip)
    }

    // Out of line so a disabled limiter costs the cache-hit path one branch.
    #[inline(never)]
    fn is_allowed_enabled(&self, client_ip: IpAddr) -> bool {
        if self.whitelist.contains(client_ip) {
            return true;
        }
        let key = self.grouping.key(client_ip);
        match self.buckets.get(&key) {
            Some(bucket) => bucket.has_tokens(),
            None => true,
        }
    }

    /// Starts a background task that evicts stale subnet buckets.
    pub fn start_eviction_task(&self) {
        if !self.enabled || self.stale_ttl_ns == 0 {
            return;
        }
        let buckets = Arc::clone(&self.buckets);
        let stale_ttl_ns = self.stale_ttl_ns;
        let interval_secs = (stale_ttl_ns / 1_000_000_000).max(30);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let now_ns = coarse_now_ns();
                buckets.retain(|_, bucket: &mut TokenBucket| {
                    now_ns.saturating_sub(bucket.last_refill_ns()) < stale_ttl_ns
                });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper: creates an enabled config with QPS=1 (negligible refill in test time).
    ///
    /// `burst=N` means exactly N allowed queries before rate limiting kicks in.
    fn config_with_burst(burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            queries_per_second: 1,
            burst_size: burst,
            ipv4_prefix_len: 24,
            ipv6_prefix_len: 48,
            whitelist: vec![],
            nxdomain_per_second: 1,
            slip_ratio: 0,
            dry_run: false,
            stale_entry_ttl_secs: 300,
            tcp_max_connections_per_ip: 30,
            dot_max_connections_per_ip: 15,
            doq_max_connections_per_ip: 15,
        }
    }

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    #[test]
    fn disabled_always_allows() {
        let limiter = DnsRateLimiter::disabled();
        for _ in 0..1000 {
            assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        }
    }

    #[test]
    fn allows_within_burst() {
        // burst=10 → exactly 10 allowed queries
        let limiter = DnsRateLimiter::new(&config_with_burst(10));
        for _ in 0..10 {
            assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        }
    }

    #[test]
    fn refuses_after_burst_exhausted() {
        // burst=5 → 5 allowed, 6th is refused
        let limiter = DnsRateLimiter::new(&config_with_burst(5));
        for _ in 0..5 {
            assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        }
        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Refuse);
    }

    #[test]
    fn whitelist_bypasses_limit() {
        let mut config = config_with_burst(0);
        config.whitelist = vec!["10.0.0.0/8".to_string()];
        let limiter = DnsRateLimiter::new(&config);

        // burst=0 but whitelisted — always allowed
        for _ in 0..100 {
            assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        }
    }

    #[test]
    fn dry_run_allows_but_signals() {
        // burst=1 → 1 allowed, then dry-run signals
        let mut config = config_with_burst(1);
        config.dry_run = true;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        assert_eq!(limiter.check(CLIENT), RateLimitDecision::DryRunWouldRefuse);
    }

    #[test]
    fn slip_ratio_produces_tc() {
        // burst=1 → 1st allowed, rest are rate-limited with slip
        let mut config = config_with_burst(1);
        config.slip_ratio = 2;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);

        let mut slips = 0;
        let mut refuses = 0;
        for _ in 0..100 {
            match limiter.check(CLIENT) {
                RateLimitDecision::Slip => slips += 1,
                RateLimitDecision::Refuse => refuses += 1,
                other => panic!("unexpected decision: {:?}", other),
            }
        }
        assert_eq!(slips, 50);
        assert_eq!(refuses, 50);
    }

    #[test]
    fn only_the_over_budget_nxdomain_gets_the_action() {
        // NX budget = nx_qps * NX_BURST_MULTIPLIER = 1 * 2 = 2 answers.
        let mut config = config_with_burst(20);
        config.nxdomain_per_second = 1;
        config.slip_ratio = 2;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Allow);
        assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Allow);
        // Over budget: handled by the configured action (slip, then refuse).
        assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Slip);
        assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Refuse);

        // The subnet's other queries are still admitted.
        assert!(limiter.is_allowed(CLIENT));
        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);

        // Another subnet has its own NXDOMAIN budget.
        let other: IpAddr = "10.0.9.1".parse().unwrap();
        assert_eq!(limiter.charge_nxdomain(other), RateLimitDecision::Allow);
    }

    #[test]
    fn nxdomain_budget_dry_run_only_signals() {
        let mut config = config_with_burst(20);
        config.dry_run = true;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Allow);
        assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Allow);
        assert_eq!(
            limiter.charge_nxdomain(CLIENT),
            RateLimitDecision::DryRunWouldRefuse
        );
    }

    #[test]
    fn nxdomain_charges_skip_whitelisted_and_zero_budget() {
        let mut whitelisted = config_with_burst(20);
        whitelisted.whitelist = vec!["10.0.0.0/8".to_string()];
        let mut unbudgeted = config_with_burst(20);
        unbudgeted.nxdomain_per_second = 0;

        for config in [whitelisted, unbudgeted] {
            let limiter = DnsRateLimiter::new(&config);
            for _ in 0..10 {
                assert_eq!(limiter.charge_nxdomain(CLIENT), RateLimitDecision::Allow);
            }
        }
    }

    #[test]
    fn same_subnet_shares_bucket() {
        // burst=1 → only 1 allowed total for the /24 subnet
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.200".parse().unwrap();

        // ip_a consumes the single token
        assert_eq!(limiter.check(ip_a), RateLimitDecision::Allow);
        // ip_b same /24, bucket exhausted → refused
        assert_eq!(limiter.check(ip_b), RateLimitDecision::Refuse);
    }

    #[test]
    fn different_subnets_have_independent_buckets() {
        // burst=1 → each subnet gets exactly 1 allowed
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        let ip_a: IpAddr = "10.0.1.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.2.1".parse().unwrap();

        assert_eq!(limiter.check(ip_a), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip_b), RateLimitDecision::Allow);
        // Both subnets exhausted independently
        assert_eq!(limiter.check(ip_a), RateLimitDecision::Refuse);
        assert_eq!(limiter.check(ip_b), RateLimitDecision::Refuse);
    }

    #[test]
    fn first_query_from_new_subnet_always_allowed() {
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Refuse);
    }

    #[test]
    fn slip_ratio_zero_disables_tc() {
        let mut config = config_with_burst(1);
        config.slip_ratio = 0;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.check(CLIENT), RateLimitDecision::Allow);
        for _ in 0..50 {
            assert_eq!(limiter.check(CLIENT), RateLimitDecision::Refuse);
        }
    }

    #[test]
    fn ipv6_client_rate_limited() {
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(limiter.check(ipv6), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ipv6), RateLimitDecision::Refuse);
    }

    #[test]
    fn creates_bucket_per_new_subnet() {
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        for i in 1..=4u8 {
            let ip: IpAddr = format!("10.0.{i}.1").parse().unwrap();
            assert_eq!(limiter.check(ip), RateLimitDecision::Allow);
        }
        assert_eq!(limiter.buckets.len(), 4);
    }
}
