use crate::errors::domain_error::DomainError;
use crate::value_objects::validators::exceeds_chars;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Shortest expiry a temporary managed domain may carry.
pub const MIN_MANAGED_DOMAIN_EXPIRY: Duration = Duration::from_secs(60);
/// Longest expiry a temporary managed domain may carry: 30 days.
pub const MAX_MANAGED_DOMAIN_EXPIRY: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainAction {
    Allow,
    Deny,
}

impl DomainAction {
    pub fn to_str(&self) -> &'static str {
        match self {
            DomainAction::Allow => "allow",
            DomainAction::Deny => "deny",
        }
    }
}

impl std::str::FromStr for DomainAction {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(DomainAction::Allow),
            "deny" => Ok(DomainAction::Deny),
            other => Err(DomainError::InvalidInput(format!(
                "invalid action '{other}': expected 'allow' or 'deny'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedDomain {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub domain: Arc<str>,
    pub action: DomainAction,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub enabled: bool,
    pub service_id: Option<Arc<str>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// When the rule stops applying and is removed; `None` for a rule that
    /// never expires.
    pub expires_at: Option<String>,
}

impl ManagedDomain {
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Managed domain name cannot be empty".to_string());
        }
        if exceeds_chars(name, 200) {
            return Err("Managed domain name cannot exceed 200 characters".to_string());
        }
        Ok(())
    }

    pub fn validate_domain(domain: &str) -> Result<(), String> {
        if domain.is_empty() {
            return Err("Domain cannot be empty".to_string());
        }
        if domain.len() > 253 {
            return Err("Domain cannot exceed 253 characters".to_string());
        }

        if domain.contains('*') && !domain.starts_with("*.") {
            return Err("Wildcard must be a prefix: use '*.example.com' format".to_string());
        }

        let check = domain.strip_prefix("*.").unwrap_or(domain);
        if check.is_empty() || check.starts_with('.') || check.contains("..") {
            return Err("Domain cannot contain an empty label".to_string());
        }

        let valid = check
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
        if !valid {
            return Err(
                "Domain contains invalid characters (only alphanumeric, hyphens, dots and underscores are allowed)".to_string(),
            );
        }
        Ok(())
    }

    pub fn validate_expiry(expires_in: Duration) -> Result<(), String> {
        if !(MIN_MANAGED_DOMAIN_EXPIRY..=MAX_MANAGED_DOMAIN_EXPIRY).contains(&expires_in) {
            return Err(format!(
                "Expiry must be between {} and {} seconds",
                MIN_MANAGED_DOMAIN_EXPIRY.as_secs(),
                MAX_MANAGED_DOMAIN_EXPIRY.as_secs()
            ));
        }
        Ok(())
    }
}
