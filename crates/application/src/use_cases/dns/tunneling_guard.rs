use ferrous_dns_domain::{RecordType, TunnelingAction, TunnelingDetectionConfig};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Outcome of the hot-path tunneling check (phase 1).
pub(super) enum TunnelingVerdict {
    /// No tunneling signal detected.
    Clean,
    /// A tunneling signal was detected with measurable details.
    Detected {
        signal: &'static str,
        measured: f32,
        threshold: f32,
    },
}

/// Parsed CIDR range for client whitelist matching.
struct CidrRange {
    network: u128,
    mask: u128,
}

impl CidrRange {
    fn parse(cidr: &str) -> Option<Self> {
        let (addr_str, prefix_str) = cidr.split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;

        if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return None;
            }
            let v4_bits = u32::from(v4);
            let v4_mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            // Map to IPv4-mapped IPv6 space: ::ffff:a.b.c.d
            let mapped = (v4_bits as u128) | 0xFFFF_0000_0000u128;
            let mapped_mask = (v4_mask as u128) | 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000u128;
            Some(Self {
                network: mapped & mapped_mask,
                mask: mapped_mask,
            })
        } else if let Ok(v6) = addr_str.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return None;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0u128
            } else {
                (u128::MAX >> (128 - prefix)) << (128 - prefix)
            };
            Some(Self {
                network: bits & mask,
                mask,
            })
        } else {
            None
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let bits = match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128 | 0xFFFF_0000_0000u128,
            IpAddr::V6(v6) => u128::from(v6),
        };
        (bits & self.mask) == self.network
    }
}

/// Guards DNS queries against tunneling attempts on the hot path.
///
/// Performs O(1) checks only: FQDN length, label length, and NULL record type.
/// Statistical analysis (entropy, query rate) runs in a separate background task.
pub(super) struct TunnelingGuard {
    enabled: bool,
    action: TunnelingAction,
    max_fqdn_length: usize,
    max_label_length: usize,
    block_null_queries: bool,
    domain_whitelist: HashSet<Box<str>>,
    client_whitelist: Vec<CidrRange>,
}

impl TunnelingGuard {
    /// Creates a guard from the domain-layer configuration.
    pub(super) fn from_config(config: &TunnelingDetectionConfig) -> Self {
        Self {
            enabled: config.enabled,
            action: config.action,
            max_fqdn_length: config.max_fqdn_length,
            max_label_length: config.max_label_length,
            block_null_queries: config.block_null_queries,
            domain_whitelist: config
                .domain_whitelist
                .iter()
                .map(|s| s.to_lowercase().into_boxed_str())
                .collect(),
            client_whitelist: config
                .client_whitelist
                .iter()
                .filter_map(|s| CidrRange::parse(s))
                .collect(),
        }
    }

    /// Creates a disabled guard that never triggers.
    pub(super) fn disabled() -> Self {
        Self {
            enabled: false,
            action: TunnelingAction::Block,
            max_fqdn_length: 120,
            max_label_length: 50,
            block_null_queries: true,
            domain_whitelist: HashSet::new(),
            client_whitelist: Vec::new(),
        }
    }

    /// Returns the configured action for detected tunneling.
    pub(super) fn action(&self) -> TunnelingAction {
        self.action
    }

    /// Returns `true` if the client IP is in the configured whitelist.
    pub(super) fn is_client_whitelisted(&self, client_ip: IpAddr) -> bool {
        self.client_whitelist
            .iter()
            .any(|cidr| cidr.contains(client_ip))
    }

    /// Performs O(1) tunneling checks on the hot path.
    ///
    /// Zero heap allocations: `domain` is `&str`, labels are slices.
    pub(super) fn check(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> TunnelingVerdict {
        if !self.enabled {
            return TunnelingVerdict::Clean;
        }

        if self.is_client_whitelisted(client_ip) {
            return TunnelingVerdict::Clean;
        }

        // O(1) HashSet lookup (case-insensitive via pre-lowercased keys)
        if domain.len() <= 253 {
            let mut buf = [0u8; 253];
            let bytes = domain.as_bytes();
            let len = bytes.len();
            for (i, &b) in bytes.iter().enumerate() {
                buf[i] = b.to_ascii_lowercase();
            }
            let lower = unsafe { std::str::from_utf8_unchecked(&buf[..len]) };
            if self.domain_whitelist.contains(lower) {
                return TunnelingVerdict::Clean;
            }
        }

        if domain.len() > self.max_fqdn_length {
            return TunnelingVerdict::Detected {
                signal: "fqdn_length",
                measured: domain.len() as f32,
                threshold: self.max_fqdn_length as f32,
            };
        }

        for label in domain.split('.') {
            if label.len() > self.max_label_length {
                return TunnelingVerdict::Detected {
                    signal: "label_length",
                    measured: label.len() as f32,
                    threshold: self.max_label_length as f32,
                };
            }
        }

        if self.block_null_queries && record_type == RecordType::NULL {
            return TunnelingVerdict::Detected {
                signal: "null_record_type",
                measured: 1.0,
                threshold: 0.0,
            };
        }

        TunnelingVerdict::Clean
    }
}

/// Event emitted to the background analysis task after each query.
pub struct TunnelingAnalysisEvent {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub was_nxdomain: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    fn guard_with_defaults() -> TunnelingGuard {
        TunnelingGuard::from_config(&TunnelingDetectionConfig {
            enabled: true,
            ..Default::default()
        })
    }

    #[test]
    fn disabled_guard_always_returns_clean() {
        let guard = TunnelingGuard::disabled();
        let result = guard.check("x".repeat(200).as_str(), RecordType::NULL, TEST_IP);
        assert!(matches!(result, TunnelingVerdict::Clean));
    }

    #[test]
    fn short_domain_passes_check() {
        let guard = guard_with_defaults();
        let result = guard.check("example.com", RecordType::A, TEST_IP);
        assert!(matches!(result, TunnelingVerdict::Clean));
    }

    #[test]
    fn long_fqdn_triggers_detection() {
        let guard = guard_with_defaults();
        let long = format!("{}.example.com", "a".repeat(120));
        let result = guard.check(&long, RecordType::A, TEST_IP);
        assert!(matches!(
            result,
            TunnelingVerdict::Detected {
                signal: "fqdn_length",
                ..
            }
        ));
    }

    #[test]
    fn long_label_triggers_detection() {
        let guard = guard_with_defaults();
        let domain = format!("{}.example.com", "b".repeat(51));
        let result = guard.check(&domain, RecordType::A, TEST_IP);
        assert!(matches!(
            result,
            TunnelingVerdict::Detected {
                signal: "label_length",
                ..
            }
        ));
    }

    #[test]
    fn null_record_type_triggers_detection() {
        let guard = guard_with_defaults();
        let result = guard.check("example.com", RecordType::NULL, TEST_IP);
        assert!(matches!(
            result,
            TunnelingVerdict::Detected {
                signal: "null_record_type",
                ..
            }
        ));
    }

    #[test]
    fn whitelisted_domain_passes_check() {
        let guard = TunnelingGuard::from_config(&TunnelingDetectionConfig {
            enabled: true,
            domain_whitelist: vec!["long-cdn.example.com".to_string()],
            ..Default::default()
        });
        let result = guard.check("long-cdn.example.com", RecordType::NULL, TEST_IP);
        assert!(matches!(result, TunnelingVerdict::Clean));
    }

    #[test]
    fn whitelisted_client_passes_check() {
        let guard = TunnelingGuard::from_config(&TunnelingDetectionConfig {
            enabled: true,
            client_whitelist: vec!["192.168.1.0/24".to_string()],
            ..Default::default()
        });
        let long = "x".repeat(200);
        let result = guard.check(&long, RecordType::NULL, TEST_IP);
        assert!(matches!(result, TunnelingVerdict::Clean));
    }

    #[test]
    fn non_whitelisted_client_is_checked() {
        let guard = TunnelingGuard::from_config(&TunnelingDetectionConfig {
            enabled: true,
            client_whitelist: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        });
        let result = guard.check("example.com", RecordType::NULL, TEST_IP);
        assert!(matches!(
            result,
            TunnelingVerdict::Detected {
                signal: "null_record_type",
                ..
            }
        ));
    }

    #[test]
    fn normal_record_types_pass() {
        let guard = guard_with_defaults();
        for rt in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::MX,
        ] {
            let result = guard.check("example.com", rt, TEST_IP);
            assert!(matches!(result, TunnelingVerdict::Clean));
        }
    }
}
