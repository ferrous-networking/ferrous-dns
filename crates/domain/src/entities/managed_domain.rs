use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(DomainAction::Allow),
            "deny" => Ok(DomainAction::Deny),
            _ => Err(()),
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
}

impl ManagedDomain {
    pub fn new(
        id: Option<i64>,
        name: Arc<str>,
        domain: Arc<str>,
        action: DomainAction,
        group_id: i64,
        comment: Option<Arc<str>>,
        enabled: bool,
    ) -> Self {
        Self {
            id,
            name,
            domain,
            action,
            group_id,
            comment,
            enabled,
            service_id: None,
            created_at: None,
            updated_at: None,
        }
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Managed domain name cannot be empty".to_string());
        }
        if name.len() > 200 {
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

        let check = if let Some(rest) = domain.strip_prefix("*.") {
            rest
        } else {
            domain
        };

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

    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(c) = comment {
            if c.len() > 500 {
                return Err("Comment cannot exceed 500 characters".to_string());
            }
        }
        Ok(())
    }
}
