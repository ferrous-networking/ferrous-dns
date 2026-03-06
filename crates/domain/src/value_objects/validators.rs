use std::sync::Arc;

pub fn validate_source_name(name: &str, entity: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{entity} name cannot be empty"));
    }
    if name.len() > 200 {
        return Err(format!("{entity} name cannot exceed 200 characters"));
    }
    Ok(())
}

pub fn validate_url(url: &Option<Arc<str>>) -> Result<(), String> {
    if let Some(u) = url {
        if u.len() > 2048 {
            return Err("URL cannot exceed 2048 characters".to_string());
        }
        if !u.starts_with("http://") && !u.starts_with("https://") {
            return Err("URL must start with http:// or https://".to_string());
        }
    }
    Ok(())
}

pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
    if let Some(c) = comment {
        if c.len() > 500 {
            return Err("Comment cannot exceed 500 characters".to_string());
        }
    }
    Ok(())
}
