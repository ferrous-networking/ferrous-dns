use crate::value_objects::validators;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSource {
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

/// How the last download of a source's list went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListSyncStatus {
    /// Downloaded with content new to the copy in use, or as the first copy.
    Updated,
    /// Downloaded with the same content as the copy in use.
    Unchanged,
    /// The download failed and the previous copy stays in use.
    FailedKeptCopy,
    /// The download failed and there is no copy to use.
    FailedNoCopy,
}

impl ListSyncStatus {
    /// The value stored in the sources' `last_status` column.
    pub fn code(self) -> i64 {
        match self {
            Self::Updated => 1,
            Self::Unchanged => 2,
            Self::FailedKeptCopy => 3,
            Self::FailedNoCopy => 4,
        }
    }

    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            1 => Some(Self::Updated),
            2 => Some(Self::Unchanged),
            3 => Some(Self::FailedKeptCopy),
            4 => Some(Self::FailedNoCopy),
            _ => None,
        }
    }

    /// Whether the list was downloaded.
    pub fn downloaded(self) -> bool {
        matches!(self, Self::Updated | Self::Unchanged)
    }
}

impl BlocklistSource {
    pub fn validate_name(name: &str) -> Result<(), String> {
        validators::validate_source_name(name, "Blocklist source")
    }
}
