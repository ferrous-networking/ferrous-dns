use crate::ports::{DnsResolution, ResponseIpFilterStore};
use ferrous_dns_domain::ResponseIpFilterAction;
use std::sync::Arc;

/// Guards DNS responses against known C2 IPs from threat feeds.
///
/// Checks whether any IP address in a resolution belongs to a downloaded
/// C2 IP blocklist. When `store` is `None`, the guard is disabled and never matches.
pub(super) struct ResponseIpFilterGuard {
    action: ResponseIpFilterAction,
    store: Option<Arc<dyn ResponseIpFilterStore>>,
}

impl ResponseIpFilterGuard {
    /// Creates an active guard with the given store for IP lookups.
    pub(super) fn new(
        action: ResponseIpFilterAction,
        store: Arc<dyn ResponseIpFilterStore>,
    ) -> Self {
        Self {
            action,
            store: Some(store),
        }
    }

    /// Creates a disabled guard that never blocks.
    pub(super) fn disabled() -> Self {
        Self {
            action: ResponseIpFilterAction::Block,
            store: None,
        }
    }

    /// Returns the configured action for detected C2 IPs.
    pub(super) fn action(&self) -> ResponseIpFilterAction {
        self.action
    }

    /// Returns `true` if any IP in the resolution is a known C2 IP.
    ///
    /// Iterates `resolution.addresses` (typically 1-4 IPs) and calls the
    /// store's O(1) `is_blocked_ip()` for each. Short-circuits on first match.
    pub(super) fn has_blocked_ip(&self, resolution: &DnsResolution) -> bool {
        let Some(ref store) = self.store else {
            return false;
        };
        resolution
            .addresses
            .iter()
            .any(|ip| store.is_blocked_ip(ip))
    }
}
