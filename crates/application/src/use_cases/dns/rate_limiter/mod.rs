mod subnet_key;
mod token_bucket;
mod whitelist_set;

use dashmap::DashMap;
use ferrous_dns_domain::RateLimitConfig;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use subnet_key::SubnetKey;
use token_bucket::TokenBucket;
use whitelist_set::WhitelistSet;

/// NX burst capacity is this multiple of `nxdomain_per_second`.
const NX_BURST_MULTIPLIER: u32 = 2;

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
    v4_prefix: u8,
    v6_prefix: u8,
    slip_ratio: u32,
    stale_ttl_ns: u64,
    whitelist: WhitelistSet,
    buckets: Arc<DashMap<SubnetKey, TokenBucket, FxBuildHasher>>,
    slip_counter: AtomicU64,
}

impl DnsRateLimiter {
    /// Creates a rate limiter from configuration.
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            enabled: config.enabled,
            dry_run: config.dry_run,
            qps: config.queries_per_second,
            burst: config.burst_size,
            nx_qps: config.nxdomain_per_second,
            v4_prefix: config.ipv4_prefix_len,
            v6_prefix: config.ipv6_prefix_len,
            slip_ratio: config.slip_ratio,
            stale_ttl_ns: config.stale_entry_ttl_secs * 1_000_000_000,
            whitelist: WhitelistSet::from_cidrs(&config.whitelist),
            buckets: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            slip_counter: AtomicU64::new(0),
        }
    }

    /// Creates a disabled limiter that always returns `Allow`.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            dry_run: false,
            qps: 0,
            burst: 0,
            nx_qps: 0,
            v4_prefix: 24,
            v6_prefix: 56,
            slip_ratio: 0,
            stale_ttl_ns: 0,
            whitelist: WhitelistSet::from_cidrs(&[]),
            buckets: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            slip_counter: AtomicU64::new(0),
        }
    }

    /// Checks whether a query from `client_ip` should be allowed.
    ///
    /// This is called on the DNS hot path — zero allocations, atomic-only state.
    #[inline]
    pub fn check(&self, client_ip: IpAddr, is_nxdomain: bool) -> RateLimitDecision {
        if !self.enabled {
            return RateLimitDecision::Allow;
        }
        if self.whitelist.contains(client_ip) {
            return RateLimitDecision::Allow;
        }

        let now_ns = coarse_now_ns();
        let key = SubnetKey::from_ip(client_ip, self.v4_prefix, self.v6_prefix);

        let allowed = {
            let bucket = self.buckets.entry(key).or_insert_with(|| {
                TokenBucket::new(self.burst, self.nx_qps * NX_BURST_MULTIPLIER, now_ns)
            });
            bucket.try_consume(now_ns, self.qps, self.burst, is_nxdomain, self.nx_qps)
        };

        if allowed {
            return RateLimitDecision::Allow;
        }

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
        if !self.enabled {
            return true;
        }
        if self.whitelist.contains(client_ip) {
            return true;
        }
        let key = SubnetKey::from_ip(client_ip, self.v4_prefix, self.v6_prefix);
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

#[cfg(target_os = "linux")]
#[inline]
fn coarse_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is stack-allocated and valid; clock_gettime only writes into the provided pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(not(target_os = "linux"))]
#[inline]
fn coarse_now_ns() -> u64 {
    use std::sync::LazyLock;
    use std::time::Instant;
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_nanos() as u64
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
        }
    }

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    #[test]
    fn disabled_always_allows() {
        let limiter = DnsRateLimiter::disabled();
        for _ in 0..1000 {
            assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        }
    }

    #[test]
    fn allows_within_burst() {
        // burst=10 → exactly 10 allowed queries
        let limiter = DnsRateLimiter::new(&config_with_burst(10));
        for _ in 0..10 {
            assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        }
    }

    #[test]
    fn refuses_after_burst_exhausted() {
        // burst=5 → 5 allowed, 6th is refused
        let limiter = DnsRateLimiter::new(&config_with_burst(5));
        for _ in 0..5 {
            assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        }
        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Refuse);
    }

    #[test]
    fn whitelist_bypasses_limit() {
        let mut config = config_with_burst(0);
        config.whitelist = vec!["10.0.0.0/8".to_string()];
        let limiter = DnsRateLimiter::new(&config);

        // burst=0 but whitelisted — always allowed
        for _ in 0..100 {
            assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        }
    }

    #[test]
    fn dry_run_allows_but_signals() {
        // burst=1 → 1 allowed, then dry-run signals
        let mut config = config_with_burst(1);
        config.dry_run = true;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(CLIENT, false),
            RateLimitDecision::DryRunWouldRefuse
        );
    }

    #[test]
    fn slip_ratio_produces_tc() {
        // burst=1 → 1st allowed, rest are rate-limited with slip
        let mut config = config_with_burst(1);
        config.slip_ratio = 2;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);

        let mut slips = 0;
        let mut refuses = 0;
        for _ in 0..100 {
            match limiter.check(CLIENT, false) {
                RateLimitDecision::Slip => slips += 1,
                RateLimitDecision::Refuse => refuses += 1,
                other => panic!("unexpected decision: {:?}", other),
            }
        }
        assert_eq!(slips, 50);
        assert_eq!(refuses, 50);
    }

    #[test]
    fn nxdomain_has_separate_budget() {
        // NX budget = nx_qps * NX_BURST_MULTIPLIER = 1 * 2 = 2 tokens
        let mut config = config_with_burst(20);
        config.nxdomain_per_second = 1;
        let limiter = DnsRateLimiter::new(&config);

        // 2 NX queries consume 2 NX tokens
        assert_eq!(limiter.check(CLIENT, true), RateLimitDecision::Allow);
        assert_eq!(limiter.check(CLIENT, true), RateLimitDecision::Allow);
        // 3rd NX: NX budget exhausted
        assert_eq!(limiter.check(CLIENT, true), RateLimitDecision::Refuse);

        // General budget still has tokens
        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
    }

    #[test]
    fn same_subnet_shares_bucket() {
        // burst=1 → only 1 allowed total for the /24 subnet
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.200".parse().unwrap();

        // ip_a consumes the single token
        assert_eq!(limiter.check(ip_a, false), RateLimitDecision::Allow);
        // ip_b same /24, bucket exhausted → refused
        assert_eq!(limiter.check(ip_b, false), RateLimitDecision::Refuse);
    }

    #[test]
    fn different_subnets_have_independent_buckets() {
        // burst=1 → each subnet gets exactly 1 allowed
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        let ip_a: IpAddr = "10.0.1.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.2.1".parse().unwrap();

        assert_eq!(limiter.check(ip_a, false), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip_b, false), RateLimitDecision::Allow);
        // Both subnets exhausted independently
        assert_eq!(limiter.check(ip_a, false), RateLimitDecision::Refuse);
        assert_eq!(limiter.check(ip_b, false), RateLimitDecision::Refuse);
    }

    #[test]
    fn first_query_from_new_subnet_always_allowed() {
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Refuse);
    }

    #[test]
    fn slip_ratio_zero_disables_tc() {
        let mut config = config_with_burst(1);
        config.slip_ratio = 0;
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Allow);
        for _ in 0..50 {
            assert_eq!(limiter.check(CLIENT, false), RateLimitDecision::Refuse);
        }
    }

    #[test]
    fn ipv6_client_rate_limited() {
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(limiter.check(ipv6, false), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ipv6, false), RateLimitDecision::Refuse);
    }

    #[test]
    fn creates_bucket_per_new_subnet() {
        let limiter = DnsRateLimiter::new(&config_with_burst(1));
        for i in 1..=4u8 {
            let ip: IpAddr = format!("10.0.{i}.1").parse().unwrap();
            assert_eq!(limiter.check(ip, false), RateLimitDecision::Allow);
        }
        assert_eq!(limiter.buckets.len(), 4);
    }
}
