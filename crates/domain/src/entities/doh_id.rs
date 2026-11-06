use crate::value_objects::validators::{exceeds_chars, MAX_LABEL_LEN};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DohId {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub client_id: Arc<str>,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl DohId {
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("DoH ID name cannot be empty".to_string());
        }

        if exceeds_chars(name, 100) {
            return Err("DoH ID name cannot exceed 100 characters".to_string());
        }

        Ok(())
    }

    /// Validates a DoH client identifier for `/dns-query/<client_id>`.
    ///
    /// Restricting identifiers to RFC 1123 lowercase DNS label characters
    /// (`a-z`, `0-9`, `-`, 1..=63 chars, no leading/trailing hyphen) keeps
    /// every registered ID usable as a future `<id>.dns.example.com` SNI label.
    pub fn validate_client_id(client_id: &str) -> Result<(), String> {
        if client_id.is_empty() {
            return Err("Client ID cannot be empty".to_string());
        }

        if exceeds_chars(client_id, MAX_LABEL_LEN) {
            return Err(format!(
                "Client ID cannot exceed {MAX_LABEL_LEN} characters"
            ));
        }

        let valid_chars = client_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid_chars {
            return Err(
                "Client ID can only contain lowercase ASCII letters (a-z), digits (0-9), and hyphens (-)"
                    .to_string(),
            );
        }

        if client_id.starts_with('-') || client_id.ends_with('-') {
            return Err("Client ID cannot start or end with a hyphen".to_string());
        }

        Ok(())
    }
}
