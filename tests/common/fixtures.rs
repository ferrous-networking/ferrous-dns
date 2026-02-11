use ferrous_dns_domain::{DnsQuery, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

/// Common test domains
pub struct TestDomains;

impl TestDomains {
    pub fn google() -> &'static str {
        "google.com"
    }

    pub fn cloudflare() -> &'static str {
        "cloudflare.com"
    }

    pub fn example() -> &'static str {
        "example.com"
    }

    pub fn blocked_ad() -> &'static str {
        "ads.evil.com"
    }

    pub fn blocked_tracker() -> &'static str {
        "tracker.malicious.net"
    }

    pub fn nonexistent() -> &'static str {
        "nonexistent.invalid"
    }

    pub fn localhost() -> &'static str {
        "localhost"
    }
}

/// Common DNS servers
pub struct TestDnsServers;

impl TestDnsServers {
    pub fn google_dns() -> &'static str {
        "8.8.8.8:53"
    }

    pub fn cloudflare_dns() -> &'static str {
        "1.1.1.1:53"
    }

    pub fn quad9_dns() -> &'static str {
        "9.9.9.9:53"
    }
}

/// Common test IPs
pub struct TestIps;

impl TestIps {
    pub fn google_ip() -> IpAddr {
        IpAddr::from_str("142.250.185.46").unwrap()
    }

    pub fn cloudflare_ip() -> IpAddr {
        IpAddr::from_str("104.16.132.229").unwrap()
    }

    pub fn example_ip() -> IpAddr {
        IpAddr::from_str("93.184.216.34").unwrap()
    }

    pub fn localhost_ipv4() -> IpAddr {
        IpAddr::from_str("127.0.0.1").unwrap()
    }

    pub fn localhost_ipv6() -> IpAddr {
        IpAddr::from_str("::1").unwrap()
    }

    pub fn client_ip() -> IpAddr {
        IpAddr::from_str("192.168.1.100").unwrap()
    }
}

/// Builder para criar queries de teste
pub struct TestQueryBuilder {
    domain: String,
    record_type: RecordType,
}

impl TestQueryBuilder {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            record_type: RecordType::A,
        }
    }

    pub fn a_record(domain: &str) -> Self {
        Self::new(domain)
    }

    pub fn aaaa_record(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            record_type: RecordType::AAAA,
        }
    }

    pub fn mx_record(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            record_type: RecordType::MX,
        }
    }

    pub fn with_type(mut self, record_type: RecordType) -> Self {
        self.record_type = record_type;
        self
    }

    pub fn build(self) -> DnsQuery {
        DnsQuery {
            domain: self.domain.into(),
            record_type: self.record_type,
        }
    }
}

/// Common test configurations
pub struct TestConfig;

impl TestConfig {
    /// Default cache size for tests
    pub fn default_cache_size() -> usize {
        512
    }

    /// Default timeout in milliseconds
    pub fn default_timeout_ms() -> u64 {
        5000
    }

    /// Test server port
    pub fn test_server_port() -> u16 {
        15353
    }

    /// Small load test size
    pub fn small_load_queries() -> usize {
        100
    }

    /// Medium load test size
    pub fn medium_load_queries() -> usize {
        1000
    }

    /// Large load test size
    pub fn large_load_queries() -> usize {
        10000
    }

    /// Stress test size
    pub fn stress_test_queries() -> usize {
        100000
    }
}

/// Performance thresholds for assertions
pub struct PerformanceThresholds;

impl PerformanceThresholds {
    /// Maximum acceptable P50 latency (ms)
    pub fn p50_latency_ms() -> u128 {
        50
    }

    /// Maximum acceptable P95 latency (ms)
    pub fn p95_latency_ms() -> u128 {
        150
    }

    /// Maximum acceptable P99 latency (ms)
    pub fn p99_latency_ms() -> u128 {
        300
    }

    /// Minimum acceptable cache hit rate (%)
    pub fn min_cache_hit_rate() -> f64 {
        0.70 // 70%
    }

    /// Minimum acceptable throughput (queries/sec)
    pub fn min_throughput_qps() -> f64 {
        1000.0
    }

    /// Maximum memory usage (MB)
    pub fn max_memory_mb() -> usize {
        100
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domains_are_valid() {
        assert!(!TestDomains::google().is_empty());
        assert!(!TestDomains::cloudflare().is_empty());
        assert!(TestDomains::example().contains('.'));
    }

    #[test]
    fn test_ips_are_valid() {
        assert!(TestIps::google_ip().is_ipv4());
        assert!(TestIps::localhost_ipv6().is_ipv6());
    }

    #[test]
    fn test_query_builder() {
        let query = TestQueryBuilder::a_record("test.com").build();
        assert_eq!(&*query.domain, "test.com");
        assert_eq!(query.record_type, RecordType::A);

        let query = TestQueryBuilder::aaaa_record("test.com").build();
        assert_eq!(query.record_type, RecordType::AAAA);
    }

    #[test]
    fn test_config_values() {
        assert!(TestConfig::default_cache_size() > 0);
        assert!(TestConfig::default_timeout_ms() > 0);
        assert!(TestConfig::test_server_port() > 1024);
    }

    #[test]
    fn test_thresholds() {
        assert!(PerformanceThresholds::p50_latency_ms() < PerformanceThresholds::p95_latency_ms());
        assert!(PerformanceThresholds::p95_latency_ms() < PerformanceThresholds::p99_latency_ms());
        assert!(PerformanceThresholds::min_cache_hit_rate() > 0.0);
        assert!(PerformanceThresholds::min_cache_hit_rate() <= 1.0);
    }
}
