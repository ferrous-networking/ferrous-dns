use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

/// Default NAT64 prefix — the RFC 6052 §2.1 well-known prefix, always `/96`.
pub const DEFAULT_DNS64_PREFIX: &str = "64:ff9b::/96";

fn default_dns64_prefix() -> String {
    DEFAULT_DNS64_PREFIX.to_string()
}

/// DNS64 (RFC 6147) AAAA synthesis for IPv6-only clients.
///
/// When enabled, an `AAAA` query that comes back NODATA (the name has A records
/// but no AAAA) is answered with synthetic AAAA records that embed each IPv4 into
/// the `/96` NAT64 `prefix`. This only produces working answers when a NAT64
/// gateway is present on the network, so it is **off by default**.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Dns64Config {
    /// Off by default — synthesizing without a NAT64 gateway breaks IPv6 clients.
    pub enabled: bool,

    /// NAT64 prefix in CIDR form. Only `/96` is supported; any other length or a
    /// malformed value disables DNS64 with a warning (fail-soft) — see
    /// [`Dns64Config::parsed_prefix`].
    #[serde(default = "default_dns64_prefix")]
    pub prefix: String,
}

impl Default for Dns64Config {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: default_dns64_prefix(),
        }
    }
}

impl Dns64Config {
    /// Parses `prefix` and returns the `/96` network address (last 32 bits
    /// zeroed), or `None` when the value is malformed or carries a prefix length
    /// other than `/96`. A bare address with no `/length` is treated as `/96`.
    pub fn parsed_prefix(&self) -> Option<Ipv6Addr> {
        let trimmed = self.prefix.trim();
        let addr_str = match trimmed.split_once('/') {
            Some((addr, len)) => {
                if len.trim() != "96" {
                    return None;
                }
                addr
            }
            None => trimmed,
        };

        let ip: Ipv6Addr = addr_str.trim().parse().ok()?;
        let mut octets = ip.octets();
        octets[12..16].fill(0);
        Some(Ipv6Addr::from(octets))
    }
}
