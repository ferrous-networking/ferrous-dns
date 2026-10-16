use std::net::IpAddr;

/// Longest presentation-format domain name (RFC 1035 §2.3.4).
pub const MAX_DOMAIN_LEN: usize = 253;

/// Longest domain label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Character (not byte) length check; the byte length is an upper bound, so
/// ASCII input never walks the string.
pub fn exceeds_chars(value: &str, max: usize) -> bool {
    value.len() > max && value.chars().count() > max
}

pub fn validate_source_name(name: &str, entity: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{entity} name cannot be empty"));
    }
    if exceeds_chars(name, 200) {
        return Err(format!("{entity} name cannot exceed 200 characters"));
    }
    Ok(())
}

pub fn validate_url(url: Option<&str>) -> Result<(), String> {
    if let Some(u) = url {
        if exceeds_chars(u, 2048) {
            return Err("URL cannot exceed 2048 characters".to_string());
        }
        if !u.starts_with("http://") && !u.starts_with("https://") {
            return Err("URL must start with http:// or https://".to_string());
        }
    }
    Ok(())
}

pub fn validate_comment(comment: Option<&str>) -> Result<(), String> {
    if comment.is_some_and(|c| exceeds_chars(c, 500)) {
        return Err("Comment cannot exceed 500 characters".to_string());
    }
    Ok(())
}

/// A domain name for a list matched against the exact query name: no
/// wildcard and no trailing dot, since neither could ever match.
pub fn validate_exact_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(format!("Domain cannot exceed {MAX_DOMAIN_LEN} characters"));
    }
    if domain.contains('*') {
        return Err("Wildcards are not supported: entries match the exact name".to_string());
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(
                "Domain cannot contain an empty label (no leading, trailing or double dots)"
                    .to_string(),
            );
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(format!(
                "Domain label cannot exceed {MAX_LABEL_LEN} characters"
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "Domain contains invalid characters (only letters, digits, hyphens and underscores; use punycode for internationalized names)"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// An IP address, or a CIDR whose prefix fits its family: what the detectors'
/// client whitelists parse (`guard_whitelist.rs`, `CidrRange::parse`).
pub fn validate_ip_or_cidr(entry: &str) -> Result<(), String> {
    let (addr, prefix) = match entry.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (entry, None),
    };
    let max_prefix = match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => 32,
        Ok(IpAddr::V6(_)) => 128,
        Err(_) => {
            return Err("Not an IP address or CIDR (e.g. 10.0.0.5 or 10.0.0.0/24)".to_string())
        }
    };
    match prefix.map(str::parse::<u32>) {
        None => Ok(()),
        Some(Ok(len)) if len <= max_prefix => Ok(()),
        Some(_) => Err(format!("CIDR prefix must be 0-{max_prefix}")),
    }
}
