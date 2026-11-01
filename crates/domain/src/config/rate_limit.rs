use serde::{Deserialize, Serialize};

/// Configuration for DNS query rate limiting and DoS protection.
///
/// Uses a token bucket algorithm per client subnet, one for UDP and one for
/// the stream transports. When `enabled` is `false`, all checks are bypassed
/// at zero cost.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Master switch — `false` disables all rate limiting with zero overhead.
    pub enabled: bool,

    /// Sustained queries per second allowed per subnet bucket.
    pub queries_per_second: u32,

    /// Token bucket capacity — allows short bursts above `queries_per_second`.
    pub burst_size: u32,

    /// IPv4 prefix length for subnet grouping (e.g. 24 = /24).
    pub ipv4_prefix_len: u8,

    /// IPv6 prefix length for subnet grouping (e.g. 56 = /56).
    pub ipv6_prefix_len: u8,

    /// CIDRs that bypass rate limiting entirely (e.g. `["127.0.0.0/8", "::1/128"]`).
    pub whitelist: Vec<String>,

    /// Separate, stricter budget for NXDOMAIN responses per second per subnet.
    pub nxdomain_per_second: u32,

    /// TC=1 slip ratio: every Nth rate-limited UDP response is sent as truncated
    /// (forcing TCP retry) instead of REFUSED. 0 = disabled.
    pub slip_ratio: u32,

    /// When `true`, rate-limited queries are logged but not actually refused.
    pub dry_run: bool,

    /// Seconds before an idle subnet bucket is evicted from memory.
    pub stale_entry_ttl_secs: u64,

    /// Maximum concurrent TCP DNS connections per IP address.
    pub tcp_max_connections_per_ip: u32,

    /// Maximum concurrent DNS-over-TLS connections per IP address.
    pub dot_max_connections_per_ip: u32,

    /// Maximum concurrent DNS-over-QUIC connections per IP address.
    pub doq_max_connections_per_ip: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            queries_per_second: 1000,
            burst_size: 500,
            ipv4_prefix_len: 24,
            ipv6_prefix_len: 48,
            whitelist: vec![],
            nxdomain_per_second: 50,
            slip_ratio: 0,
            dry_run: false,
            stale_entry_ttl_secs: 300,
            tcp_max_connections_per_ip: 30,
            dot_max_connections_per_ip: 15,
            doq_max_connections_per_ip: 15,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(config.burst_size, 500);
        assert_eq!(config.nxdomain_per_second, 50);
        assert_eq!(config.slip_ratio, 0);
    }
}
