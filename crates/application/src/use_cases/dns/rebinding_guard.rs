use crate::ports::DnsResolution;
use ferrous_dns_domain::PrivateIpFilter;

/// Guards DNS responses against DNS rebinding attacks.
///
/// Blocks resolutions where a public domain resolves to a private/RFC1918 IP address,
/// except for names under the local domain. Other exemptions are explicit allows
/// in the block filter, which the caller checks first.
pub(super) struct RebindingGuard {
    /// `.{local_domain}`, lowercased.
    local_domain_suffix: Option<Box<str>>,
}

impl RebindingGuard {
    /// `local_domain` (e.g. `"local"`) and its subdomains are exempt.
    pub(super) fn new(local_domain: Option<&str>) -> Self {
        Self {
            local_domain_suffix: local_domain.map(|d| format!(".{}", d.to_lowercase()).into()),
        }
    }

    /// Returns `true` when the resolution should be blocked as a rebinding attempt.
    pub(super) fn is_rebinding_attempt(&self, domain: &str, resolution: &DnsResolution) -> bool {
        if resolution.local_dns {
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
        resolution
            .addresses
            .iter()
            .any(PrivateIpFilter::is_private_ip)
    }
}
