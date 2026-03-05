use crate::ports::DnsResolution;
use ferrous_dns_domain::PrivateIpFilter;
use std::sync::Arc;

/// Guards DNS responses against DNS rebinding attacks.
///
/// Blocks resolutions where a public domain resolves to a private/RFC1918 IP address,
/// with configurable exemptions for local domains and explicitly allowlisted entries.
pub(super) struct RebindingGuard {
    enabled: bool,
    local_domain_suffix: Option<Arc<str>>,
    allowlist: Arc<[Arc<str>]>,
}

impl RebindingGuard {
    /// Creates a guard with the given configuration.
    ///
    /// `local_domain` names a TLD-like suffix (e.g. `"local"`) whose subdomains are
    /// always exempt from the rebinding check.
    /// `allowlist` contains exact domain names that are exempt regardless of resolved IP.
    pub(super) fn new(enabled: bool, local_domain: Option<&str>, allowlist: &[String]) -> Self {
        Self {
            enabled,
            local_domain_suffix: local_domain
                .map(|d| Arc::from(format!(".{}", d.to_lowercase()).as_str())),
            allowlist: allowlist
                .iter()
                .map(|s| Arc::from(s.to_lowercase().as_str()))
                .collect::<Vec<_>>()
                .into(),
        }
    }

    /// Creates a disabled guard that never blocks.
    pub(super) fn disabled() -> Self {
        Self {
            enabled: false,
            local_domain_suffix: None,
            allowlist: Arc::from([]),
        }
    }

    /// Returns `true` when the resolution should be blocked as a rebinding attempt.
    pub(super) fn is_rebinding_attempt(&self, domain: &str, resolution: &DnsResolution) -> bool {
        if !self.enabled || resolution.local_dns {
            return false;
        }
        if let Some(ref suffix) = self.local_domain_suffix {
            let exact = suffix.trim_start_matches('.');
            if domain.eq_ignore_ascii_case(exact)
                || domain
                    .get(domain.len().saturating_sub(suffix.len())..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
            {
                return false;
            }
        }
        if self
            .allowlist
            .iter()
            .any(|allowed| domain.eq_ignore_ascii_case(allowed))
        {
            return false;
        }
        resolution
            .addresses
            .iter()
            .any(PrivateIpFilter::is_private_ip)
    }
}
