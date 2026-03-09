use std::net::IpAddr;

/// Parsed CIDR whitelist for rate-limit bypass checks.
///
/// Uses linear scan — the whitelist is expected to be tiny (< 20 entries).
pub(crate) struct WhitelistSet {
    v4_entries: Vec<(u32, u32)>,
    v6_entries: Vec<(u128, u128)>,
}

impl WhitelistSet {
    /// Parses CIDR strings (e.g. `"127.0.0.0/8"`, `"::1/128"`) into masks.
    pub(crate) fn from_cidrs(cidrs: &[String]) -> Self {
        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();
        for cidr in cidrs {
            if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
                let prefix_len: u32 = match prefix_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if let Ok(addr) = addr_str.parse::<IpAddr>() {
                    match addr {
                        IpAddr::V4(v4) => {
                            let bits = u32::from(v4);
                            let mask = if prefix_len >= 32 {
                                u32::MAX
                            } else {
                                u32::MAX << (32 - prefix_len)
                            };
                            v4_entries.push((bits & mask, mask));
                        }
                        IpAddr::V6(v6) => {
                            let bits = u128::from(v6);
                            let mask = if prefix_len >= 128 {
                                u128::MAX
                            } else {
                                u128::MAX << (128 - prefix_len)
                            };
                            v6_entries.push((bits & mask, mask));
                        }
                    }
                }
            } else if let Ok(addr) = cidr.parse::<IpAddr>() {
                match addr {
                    IpAddr::V4(v4) => v4_entries.push((u32::from(v4), u32::MAX)),
                    IpAddr::V6(v6) => v6_entries.push((u128::from(v6), u128::MAX)),
                }
            }
        }
        Self {
            v4_entries,
            v6_entries,
        }
    }

    /// Returns `true` if the IP falls within any whitelisted CIDR.
    #[inline]
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                self.v4_entries
                    .iter()
                    .any(|(masked_addr, mask)| (bits & mask) == *masked_addr)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                self.v6_entries
                    .iter()
                    .any(|(masked_addr, mask)| (bits & mask) == *masked_addr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_matches_ipv4_cidr() {
        let ws = WhitelistSet::from_cidrs(&["127.0.0.0/8".to_string()]);
        assert!(ws.contains("127.0.0.1".parse().unwrap()));
        assert!(ws.contains("127.255.255.255".parse().unwrap()));
        assert!(!ws.contains("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn whitelist_matches_ipv6_cidr() {
        let ws = WhitelistSet::from_cidrs(&["::1/128".to_string()]);
        assert!(ws.contains("::1".parse().unwrap()));
        assert!(!ws.contains("::2".parse().unwrap()));
    }

    #[test]
    fn whitelist_matches_bare_ip() {
        let ws = WhitelistSet::from_cidrs(&["10.0.0.1".to_string()]);
        assert!(ws.contains("10.0.0.1".parse().unwrap()));
        assert!(!ws.contains("10.0.0.2".parse().unwrap()));
    }
}
