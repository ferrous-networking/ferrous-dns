use serde::{Deserialize, Serialize};

/// Configuration for DNS query rate limiting and DoS protection.
///
/// Uses a token bucket algorithm per client subnet. When `enabled` is `false`,
/// all checks are bypassed at zero cost.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Master switch — `false` disables all rate limiting with zero overhead.
    #[serde(default)]
    pub enabled: bool,

    /// Sustained queries per second allowed per subnet bucket.
    #[serde(default = "default_qps")]
    pub queries_per_second: u32,

    /// Token bucket capacity — allows short bursts above `queries_per_second`.
    #[serde(default = "default_burst")]
    pub burst_size: u32,

    /// IPv4 prefix length for subnet grouping (e.g. 24 = /24).
    #[serde(default = "default_v4_prefix")]
    pub ipv4_prefix_len: u8,

    /// IPv6 prefix length for subnet grouping (e.g. 56 = /56).
    #[serde(default = "default_v6_prefix")]
    pub ipv6_prefix_len: u8,

    /// CIDRs that bypass rate limiting entirely (e.g. `["127.0.0.0/8", "::1/128"]`).
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Separate, stricter budget for NXDOMAIN responses per second per subnet.
    #[serde(default = "default_nx_qps")]
    pub nxdomain_per_second: u32,

    /// TC=1 slip ratio: every Nth rate-limited UDP response is sent as truncated
    /// (forcing TCP retry) instead of REFUSED. 0 = disabled.
    #[serde(default)]
    pub slip_ratio: u32,

    /// When `true`, rate-limited queries are logged but not actually refused.
    #[serde(default)]
    pub dry_run: bool,

    /// Seconds before an idle subnet bucket is evicted from memory.
    #[serde(default = "default_stale_ttl")]
    pub stale_entry_ttl_secs: u64,

    /// Maximum concurrent TCP DNS connections per IP address.
    #[serde(default = "default_tcp_max")]
    pub tcp_max_connections_per_ip: u32,

    /// Maximum concurrent DNS-over-TLS connections per IP address.
    #[serde(default = "default_dot_max")]
    pub dot_max_connections_per_ip: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            queries_per_second: default_qps(),
            burst_size: default_burst(),
            ipv4_prefix_len: default_v4_prefix(),
            ipv6_prefix_len: default_v6_prefix(),
            whitelist: vec![],
            nxdomain_per_second: default_nx_qps(),
            slip_ratio: 0,
            dry_run: false,
            stale_entry_ttl_secs: default_stale_ttl(),
            tcp_max_connections_per_ip: default_tcp_max(),
            dot_max_connections_per_ip: default_dot_max(),
        }
    }
}

fn default_qps() -> u32 {
    1000
}

fn default_burst() -> u32 {
    500
}

fn default_v4_prefix() -> u8 {
    24
}

fn default_v6_prefix() -> u8 {
    48
}

fn default_nx_qps() -> u32 {
    50
}

fn default_stale_ttl() -> u64 {
    300
}

fn default_tcp_max() -> u32 {
    30
}

fn default_dot_max() -> u32 {
    15
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_sane() {
        let config = RateLimitConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.queries_per_second, 1000);
        assert_eq!(config.burst_size, 500);
        assert_eq!(config.ipv4_prefix_len, 24);
        assert_eq!(config.ipv6_prefix_len, 48);
        assert!(config.whitelist.is_empty());
        assert_eq!(config.nxdomain_per_second, 50);
        assert_eq!(config.slip_ratio, 0);
        assert!(!config.dry_run);
        assert_eq!(config.stale_entry_ttl_secs, 300);
        assert_eq!(config.tcp_max_connections_per_ip, 30);
        assert_eq!(config.dot_max_connections_per_ip, 15);
    }

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: RateLimitConfig = toml::from_str("").unwrap();
        assert!(!config.enabled);
        assert_eq!(config.queries_per_second, 1000);
        assert_eq!(config.burst_size, 500);
    }

    #[test]
    fn deserializes_partial_toml_preserves_defaults() {
        let toml = r#"
            enabled = true
            queries_per_second = 50
        "#;
        let config: RateLimitConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.queries_per_second, 50);
        // Rest should be defaults
        assert_eq!(config.burst_size, 500);
        assert_eq!(config.nxdomain_per_second, 50);
        assert_eq!(config.slip_ratio, 0);
    }

    #[test]
    fn deserializes_full_toml() {
        let toml = r#"
            enabled = true
            queries_per_second = 250
            burst_size = 500
            ipv4_prefix_len = 24
            ipv6_prefix_len = 48
            whitelist = ["127.0.0.0/8", "::1/128"]
            nxdomain_per_second = 50
            slip_ratio = 2
            dry_run = false
            stale_entry_ttl_secs = 300
            tcp_max_connections_per_ip = 30
            dot_max_connections_per_ip = 15
        "#;
        let config: RateLimitConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.queries_per_second, 250);
        assert_eq!(config.burst_size, 500);
        assert_eq!(config.whitelist.len(), 2);
        assert_eq!(config.slip_ratio, 2);
    }

    #[test]
    fn serializes_and_deserializes_roundtrip() {
        let original = RateLimitConfig {
            enabled: true,
            queries_per_second: 42,
            burst_size: 84,
            ipv4_prefix_len: 16,
            ipv6_prefix_len: 32,
            whitelist: vec!["10.0.0.0/8".to_string()],
            nxdomain_per_second: 10,
            slip_ratio: 3,
            dry_run: true,
            stale_entry_ttl_secs: 120,
            tcp_max_connections_per_ip: 8,
            dot_max_connections_per_ip: 4,
        };
        let toml_str = toml::to_string(&original).unwrap();
        let restored: RateLimitConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.enabled, original.enabled);
        assert_eq!(restored.queries_per_second, original.queries_per_second);
        assert_eq!(restored.burst_size, original.burst_size);
        assert_eq!(restored.ipv4_prefix_len, original.ipv4_prefix_len);
        assert_eq!(restored.ipv6_prefix_len, original.ipv6_prefix_len);
        assert_eq!(restored.whitelist, original.whitelist);
        assert_eq!(restored.nxdomain_per_second, original.nxdomain_per_second);
        assert_eq!(restored.slip_ratio, original.slip_ratio);
        assert_eq!(restored.dry_run, original.dry_run);
        assert_eq!(restored.stale_entry_ttl_secs, original.stale_entry_ttl_secs);
        assert_eq!(
            restored.tcp_max_connections_per_ip,
            original.tcp_max_connections_per_ip
        );
        assert_eq!(
            restored.dot_max_connections_per_ip,
            original.dot_max_connections_per_ip
        );
    }
}
