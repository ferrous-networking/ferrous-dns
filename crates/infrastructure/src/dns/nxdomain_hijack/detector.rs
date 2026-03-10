use crate::dns::forwarding::{MessageBuilder, ResponseParser};
use crate::dns::transport;
use dashmap::{DashMap, DashSet};
use ferrous_dns_application::ports::{NxdomainHijackIpStore, NxdomainHijackProbeTarget};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::{DnsProtocol, NxdomainHijackConfig, RecordType};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

const NS_PER_SEC: u64 = 1_000_000_000;

/// Detects ISP NXDomain hijacking by probing upstreams with `.invalid` domains.
///
/// Maintains a `DashSet` of known hijack IPs for O(1) hot-path lookups, and a
/// `DashMap` with TTL metadata for background eviction. The probe loop runs as
/// an async task, querying each upstream with random domains that must return
/// NXDOMAIN per RFC 6761.
pub struct NxdomainHijackDetector {
    config: NxdomainHijackConfig,
    /// O(1) hot-path lookup set.
    pub hijack_ips: DashSet<IpAddr, FxBuildHasher>,
    /// Last confirmation timestamp (ns) per hijack IP, for TTL-based eviction.
    pub hijack_ip_confirmed_at: DashMap<IpAddr, u64, FxBuildHasher>,
    /// Whether each upstream is currently hijacking (`true`) or clean (`false`).
    pub upstream_hijacking: DashMap<Arc<str>, bool, FxBuildHasher>,
}

impl NxdomainHijackDetector {
    /// Creates a new detector with empty state.
    pub fn new(config: &NxdomainHijackConfig) -> Self {
        Self {
            config: config.clone(),
            hijack_ips: DashSet::with_hasher(FxBuildHasher),
            hijack_ip_confirmed_at: DashMap::with_hasher(FxBuildHasher),
            upstream_hijacking: DashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Runs the probe loop, querying each upstream at the configured interval.
    ///
    /// Spawned as a background task. Runs indefinitely until the tokio runtime
    /// shuts down (same pattern as the tunneling analysis loop).
    pub async fn run_probe_loop(self: Arc<Self>, protocols: Vec<Arc<DnsProtocol>>) {
        // Pre-compute upstream keys to avoid per-cycle allocations.
        let upstream_keys: Vec<Arc<str>> = protocols
            .iter()
            .map(|p| Arc::from(p.to_string().as_str()))
            .collect();

        info!(
            interval_secs = self.config.probe_interval_secs,
            upstreams = protocols.len(),
            "NXDomain hijack probe loop starting"
        );

        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.probe_interval_secs));

        loop {
            interval.tick().await;
            self.probe_all_upstreams(&protocols, &upstream_keys).await;
        }
    }

    async fn probe_all_upstreams(
        &self,
        protocols: &[Arc<DnsProtocol>],
        upstream_keys: &[Arc<str>],
    ) {
        let timeout = Duration::from_millis(self.config.probe_timeout_ms);

        for (protocol, upstream_key) in protocols.iter().zip(upstream_keys.iter()) {
            let mut found_hijack = false;

            for _ in 0..self.config.probes_per_round {
                let probe_domain = generate_probe_domain();
                let query_bytes =
                    match MessageBuilder::build_query(&probe_domain, &RecordType::A, false) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };

                let dns_transport = match transport::get_or_create_transport(protocol) {
                    Ok(t) => t,
                    Err(e) => {
                        debug!(
                            server = %protocol,
                            error = %e,
                            "Failed to create transport for hijack probe"
                        );
                        continue;
                    }
                };

                let result = dns_transport.send(&query_bytes, timeout).await;

                match result {
                    Err(e) => {
                        debug!(server = %protocol, error = %e, "Hijack probe failed");
                    }
                    Ok(resp) => match ResponseParser::parse_bytes(resp.bytes) {
                        Ok(dns) if dns.is_nxdomain() => {}
                        Ok(dns) if !dns.addresses.is_empty() => {
                            found_hijack = true;
                            let now_ns = coarse_now_ns();
                            for ip in &dns.addresses {
                                if self.hijack_ips.insert(*ip) {
                                    warn!(
                                        server = %protocol,
                                        hijack_ip = %ip,
                                        domain = %probe_domain,
                                        "NXDomain hijack detected: upstream returned IP for .invalid domain"
                                    );
                                }
                                self.hijack_ip_confirmed_at.insert(*ip, now_ns);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            debug!(
                                server = %protocol,
                                error = %e,
                                "Failed to parse hijack probe response"
                            );
                        }
                    },
                }
            }

            let was_hijacking = self
                .upstream_hijacking
                .get(upstream_key)
                .map(|v| *v)
                .unwrap_or(false);

            if found_hijack {
                self.upstream_hijacking
                    .insert(Arc::clone(upstream_key), true);
            } else if was_hijacking {
                info!(
                    server = %protocol,
                    "Upstream recovered — no longer hijacking NXDomain responses"
                );
                self.upstream_hijacking
                    .insert(Arc::clone(upstream_key), false);
            }
        }

        debug!(
            hijack_ips = self.hijack_ips.len(),
            hijacking_upstreams = self.hijacking_upstream_count(),
            "NXDomain hijack probe cycle complete"
        );
    }
}

impl NxdomainHijackIpStore for NxdomainHijackDetector {
    fn is_hijack_ip(&self, ip: &IpAddr) -> bool {
        self.hijack_ips.contains(ip)
    }
}

impl NxdomainHijackProbeTarget for NxdomainHijackDetector {
    fn evict_stale_ips(&self) {
        let now_ns = coarse_now_ns();
        let ttl_ns = self.config.hijack_ip_ttl_secs * NS_PER_SEC;

        self.hijack_ip_confirmed_at.retain(|ip, &mut confirmed_ns| {
            let age_ns = now_ns.saturating_sub(confirmed_ns);
            if age_ns > ttl_ns {
                self.hijack_ips.remove(ip);
                debug!(ip = %ip, "Evicted stale hijack IP");
                false
            } else {
                true
            }
        });
    }

    fn hijack_ip_count(&self) -> usize {
        self.hijack_ips.len()
    }

    fn hijacking_upstream_count(&self) -> usize {
        self.upstream_hijacking
            .iter()
            .filter(|e| *e.value())
            .count()
    }
}

/// Generates a random probe domain under the `.invalid` TLD (RFC 6761).
fn generate_probe_domain() -> String {
    let random_hex = fastrand::u64(..);
    format!("{random_hex:016x}.probe.invalid")
}
