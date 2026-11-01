use crate::value_objects::validators::exceeds_chars;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub enabled: bool,
    pub comment: Option<Arc<str>>,
    pub is_default: bool,
    /// Whether the malware detectors check this group's queries. Off exempts
    /// every client in the group, as a client whitelist did.
    pub malware_detection_enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl Group {
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Group name cannot be empty".to_string());
        }

        if exceeds_chars(name, 100) {
            return Err("Group name cannot exceed 100 characters".to_string());
        }

        let valid_chars = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');

        if !valid_chars {
            return Err(
                "Group name can only contain alphanumeric characters, spaces, hyphens, and underscores"
                    .to_string(),
            );
        }

        Ok(())
    }
}
