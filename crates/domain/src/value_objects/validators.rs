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
