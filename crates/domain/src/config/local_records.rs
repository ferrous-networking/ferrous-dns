use serde::{Deserialize, Serialize};

/// Longest a DNS name may be, in bytes (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 253;

/// Longest a single DNS label may be, in bytes (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalDnsRecord {
    pub hostname: String,

    #[serde(default)]
    pub domain: Option<String>,

    pub ip: String,

    pub record_type: String,

    #[serde(default)]
    pub ttl: Option<u32>,
}

impl LocalDnsRecord {
    pub fn fqdn(&self, default_domain: &Option<String>) -> String {
        if let Some(ref domain) = self.domain {
            format!("{}.{}", self.hostname, domain)
        } else if let Some(ref default) = default_domain {
            format!("{}.{}", self.hostname, default)
        } else {
            self.hostname.clone()
        }
    }

    pub fn ttl_or_default(&self) -> u32 {
        self.ttl.unwrap_or(300)
    }

    /// True when the record covers a whole subtree instead of a single name:
    /// `*` on its own, or a `*.`-prefixed hostname such as `*.dev`.
    pub fn is_wildcard(&self) -> bool {
        is_wildcard_hostname(&self.hostname)
    }

    /// Suffix a wildcard record answers for, lowercased for matching:
    /// `*.home.lan` covers `home.lan`.
    ///
    /// `None` for an exact record, and for a wildcard with no domain to anchor
    /// it — a bare `*` would otherwise cover every query in existence.
    pub fn wildcard_suffix(&self, default_domain: &Option<String>) -> Option<String> {
        if !self.is_wildcard() {
            return None;
        }

        self.fqdn(default_domain)
            .strip_prefix("*.")
            .map(str::to_ascii_lowercase)
    }

    /// Validates the `hostname` field. A wildcard is accepted only as the
    /// leftmost label, because that is the only position the resolver can
    /// match — anything else would be stored as a record no query can reach.
    pub fn validate_hostname(hostname: &str) -> Result<(), String> {
        if hostname.is_empty() {
            return Err("Hostname cannot be empty".to_string());
        }
        if hostname.len() > MAX_NAME_LEN {
            return Err(format!("Hostname cannot exceed {MAX_NAME_LEN} characters"));
        }
        if hostname.contains('*') && !is_wildcard_hostname(hostname) {
            return Err("Wildcard must be the leftmost label: use '*' or '*.sub'".to_string());
        }

        let remainder = hostname.strip_prefix("*.").unwrap_or(hostname);
        if remainder == "*" {
            return Ok(());
        }

        validate_labels(remainder, "Hostname")
    }

    /// Validates the optional `domain` suffix. Wildcards are rejected here:
    /// the subtree is expressed by the hostname, so a `*` in the suffix would
    /// land in the middle of the composed name.
    pub fn validate_domain(domain: &str) -> Result<(), String> {
        if domain.is_empty() {
            return Err("Domain cannot be empty".to_string());
        }
        if domain.len() > MAX_NAME_LEN {
            return Err(format!("Domain cannot exceed {MAX_NAME_LEN} characters"));
        }
        if domain.contains('*') {
            return Err(
                "Domain cannot contain a wildcard: put the '*' in the hostname".to_string(),
            );
        }

        validate_labels(domain, "Domain")
    }
}

fn is_wildcard_hostname(hostname: &str) -> bool {
    hostname == "*" || hostname.starts_with("*.")
}

fn validate_labels(name: &str, field: &str) -> Result<(), String> {
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!("{field} cannot contain an empty label"));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(format!(
                "{field} label cannot exceed {MAX_LABEL_LEN} characters"
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "{field} contains invalid characters (only alphanumeric, hyphens and underscores are allowed)"
            ));
        }
    }

    Ok(())
}
