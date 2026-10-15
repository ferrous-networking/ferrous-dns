use super::blocklist_source::ListSyncStatus;
use crate::value_objects::validators;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistSource {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub url: Option<Arc<str>>,
    pub group_ids: Vec<i64>,
    pub comment: Option<Arc<str>>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_synced_at: Option<String>,
    /// How the last download of the list went; `None` before the first try.
    pub last_status: Option<ListSyncStatus>,
}

impl WhitelistSource {
    pub fn validate_name(name: &str) -> Result<(), String> {
        validators::validate_source_name(name, "Whitelist source")
    }
}
