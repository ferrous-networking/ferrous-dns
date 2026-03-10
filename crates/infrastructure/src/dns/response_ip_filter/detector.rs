use dashmap::{DashMap, DashSet};
use ferrous_dns_application::ports::{ResponseIpFilterEvictionTarget, ResponseIpFilterStore};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_domain::ResponseIpFilterConfig;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

const NS_PER_SEC: u64 = 1_000_000_000;

/// Downloads C2 IP threat feeds and provides O(1) hot-path lookup.
///
/// Maintains a `DashSet` of known C2 IPs for lock-free hot-path checks, and a
/// `DashMap` with TTL metadata for background eviction. The fetch loop runs as
/// an async task, downloading feeds at the configured interval.
pub struct ResponseIpFilterDetector {
    config: ResponseIpFilterConfig,
    /// O(1) hot-path lookup set.
    pub blocked_ips: DashSet<IpAddr, FxBuildHasher>,
    /// Last confirmation timestamp (ns) per IP, for TTL-based eviction.
    pub blocked_ip_confirmed_at: DashMap<IpAddr, u64, FxBuildHasher>,
}

impl ResponseIpFilterDetector {
    /// Creates a new detector with empty state.
    pub fn new(config: &ResponseIpFilterConfig) -> Self {
        Self {
            config: config.clone(),
            blocked_ips: DashSet::with_hasher(FxBuildHasher),
            blocked_ip_confirmed_at: DashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Runs the fetch loop, downloading IP feeds at the configured interval.
    ///
    /// Fetches immediately on startup so protection is active from the first
    /// DNS query. Then sleeps `refresh_interval_secs` between subsequent fetches.
    /// Runs until the tokio runtime shuts down (same pattern as probe/analysis loops).
    pub async fn run_fetch_loop(self: std::sync::Arc<Self>, http_client: reqwest::Client) {
        info!(
            urls = self.config.ip_list_urls.len(),
            refresh_secs = self.config.refresh_interval_secs,
            "Response IP filter fetch loop starting"
        );

        loop {
            self.fetch_all_lists(&http_client).await;

            tokio::time::sleep(Duration::from_secs(self.config.refresh_interval_secs)).await;
        }
    }

    async fn fetch_all_lists(&self, http_client: &reqwest::Client) {
        let now_ns = coarse_now_ns();
        let mut total_new = 0usize;
        let mut fetch_errors = 0usize;

        for url in &self.config.ip_list_urls {
            match fetch_ip_list(url, http_client).await {
                Ok(ips) => {
                    for ip in ips {
                        self.blocked_ip_confirmed_at.insert(ip, now_ns);
                        if self.blocked_ips.insert(ip) {
                            total_new += 1;
                        }
                    }
                }
                Err(e) => {
                    fetch_errors += 1;
                    warn!(url = %url, error = %e, "Failed to fetch C2 IP list");
                }
            }
        }

        let total = self.blocked_ips.len();
        if fetch_errors > 0 && total == 0 {
            warn!(
                failed = fetch_errors,
                urls = self.config.ip_list_urls.len(),
                "All C2 IP feeds failed — no IPs loaded for response filtering"
            );
        } else {
            info!(new_ips = total_new, total, "C2 IP list updated");
        }
    }
}

impl ResponseIpFilterStore for ResponseIpFilterDetector {
    fn is_blocked_ip(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains(ip)
    }
}

impl ResponseIpFilterEvictionTarget for ResponseIpFilterDetector {
    fn evict_stale_ips(&self) {
        let now_ns = coarse_now_ns();
        let ttl_ns = self.config.ip_ttl_secs * NS_PER_SEC;

        self.blocked_ip_confirmed_at
            .retain(|ip, &mut confirmed_ns| {
                let age_ns = now_ns.saturating_sub(confirmed_ns);
                if age_ns > ttl_ns {
                    self.blocked_ips.remove(ip);
                    debug!(ip = %ip, "Evicted stale C2 IP");
                    false
                } else {
                    true
                }
            });
    }

    fn blocked_ip_count(&self) -> usize {
        self.blocked_ips.len()
    }
}

async fn fetch_ip_list(url: &str, client: &reqwest::Client) -> Result<Vec<IpAddr>, String> {
    let response = client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("fetch error for {url}: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} for {url}", response.status().as_u16()));
    }

    let text = response
        .text()
        .await
        .map_err(|e| format!("read error for {url}: {e}"))?;

    Ok(parse_ip_list(&text))
}

/// Parses an IP list in standard format: one IP per line, `#` comments, blank lines ignored.
fn parse_ip_list(text: &str) -> Vec<IpAddr> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse::<IpAddr>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_list_handles_comments_and_blanks() {
        let text = "# Header comment\n\
                     1.2.3.4\n\
                     \n\
                     5.6.7.8 # inline comment\n\
                     # another comment\n\
                     2001:db8::1\n\
                     not_an_ip\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(ips[2], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_ip_list_empty_input() {
        assert!(parse_ip_list("").is_empty());
        assert!(parse_ip_list("# only comments\n# here").is_empty());
    }

    #[test]
    fn parse_ip_list_whitespace_only_lines() {
        let text = "  \n\t\n1.2.3.4\n   \n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_ip_list_ipv6_addresses() {
        let text = "2001:db8::1\n::1\nfe80::1\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn parse_ip_list_mixed_v4_v6() {
        let text = "1.2.3.4\n2001:db8::1\n5.6.7.8\n::1\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn parse_ip_list_skips_invalid_lines() {
        let text = "1.2.3.4\nnot_an_ip\nexample.com\n999.999.999.999\n5.6.7.8\n";
        let ips = parse_ip_list(text);
        assert_eq!(ips.len(), 2);
    }
}
