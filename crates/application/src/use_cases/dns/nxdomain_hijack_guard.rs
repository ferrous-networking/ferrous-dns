use crate::ports::{DnsResolution, NxdomainHijackIpStore};
use ferrous_dns_domain::NxdomainHijackAction;
use std::sync::Arc;

/// Guards DNS responses against NXDomain hijacking by ISPs.
///
/// Checks whether any IP address in a resolution belongs to a known ISP
/// advertising server that intercepts NXDOMAIN responses.
/// When `store` is `None`, the guard is disabled and never matches.
pub(super) struct NxdomainHijackGuard {
    action: NxdomainHijackAction,
    store: Option<Arc<dyn NxdomainHijackIpStore>>,
}

impl NxdomainHijackGuard {
    /// Creates an active guard with the given store for IP lookups.
    pub(super) fn new(action: NxdomainHijackAction, store: Arc<dyn NxdomainHijackIpStore>) -> Self {
        Self {
            action,
            store: Some(store),
        }
    }

    /// Creates a disabled guard that never blocks.
    pub(super) fn disabled() -> Self {
        Self {
            action: NxdomainHijackAction::Block,
            store: None,
        }
    }

    /// Returns the configured action for detected hijacks.
    pub(super) fn action(&self) -> NxdomainHijackAction {
        self.action
    }

    /// Returns `true` if any IP in the resolution is a known hijack IP.
    ///
    /// Iterates `resolution.addresses` (typically 1–4 IPs) and calls the
    /// store's O(1) `is_hijack_ip()` for each. Short-circuits on first match.
    pub(super) fn is_hijacked_response(&self, resolution: &DnsResolution) -> bool {
        let Some(ref store) = self.store else {
            return false;
        };
        resolution.addresses.iter().any(|ip| store.is_hijack_ip(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    struct AlwaysHijackStore;
    impl NxdomainHijackIpStore for AlwaysHijackStore {
        fn is_hijack_ip(&self, _ip: &IpAddr) -> bool {
            true
        }
    }

    struct NeverHijackStore;
    impl NxdomainHijackIpStore for NeverHijackStore {
        fn is_hijack_ip(&self, _ip: &IpAddr) -> bool {
            false
        }
    }

    fn resolution_with_ips(ips: Vec<IpAddr>) -> DnsResolution {
        DnsResolution {
            addresses: Arc::new(ips),
            cache_hit: false,
            local_dns: false,
            dnssec_status: None,
            cname_chain: Arc::from([]),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: None,
            negative_soa_ttl: None,
            upstream_wire_data: None,
        }
    }

    #[test]
    fn disabled_guard_never_matches() {
        let guard = NxdomainHijackGuard::disabled();
        let resolution = resolution_with_ips(vec!["1.2.3.4".parse().unwrap()]);
        assert!(!guard.is_hijacked_response(&resolution));
    }

    #[test]
    fn empty_addresses_never_matches() {
        let guard =
            NxdomainHijackGuard::new(NxdomainHijackAction::Block, Arc::new(AlwaysHijackStore));
        let resolution = resolution_with_ips(vec![]);
        assert!(!guard.is_hijacked_response(&resolution));
    }

    #[test]
    fn store_with_no_match_returns_false() {
        let guard =
            NxdomainHijackGuard::new(NxdomainHijackAction::Block, Arc::new(NeverHijackStore));
        let resolution = resolution_with_ips(vec!["1.2.3.4".parse().unwrap()]);
        assert!(!guard.is_hijacked_response(&resolution));
    }

    #[test]
    fn store_with_match_returns_true() {
        let guard =
            NxdomainHijackGuard::new(NxdomainHijackAction::Block, Arc::new(AlwaysHijackStore));
        let resolution = resolution_with_ips(vec!["1.2.3.4".parse().unwrap()]);
        assert!(guard.is_hijacked_response(&resolution));
    }

    #[test]
    fn action_returns_configured_value() {
        let guard =
            NxdomainHijackGuard::new(NxdomainHijackAction::Alert, Arc::new(NeverHijackStore));
        assert_eq!(guard.action(), NxdomainHijackAction::Alert);
    }
}
