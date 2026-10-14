use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::dto::crud::{Processed, StringOrArray};

/// Pi-hole v6 list type. Blocklist and allowlist sources live in separate
/// tables, so a list is only identified by its address together with its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    Allow,
    Block,
}

impl ListType {
    /// Case-insensitive, as in Pi-hole FTL.
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("allow") {
            Some(Self::Allow)
        } else if s.eq_ignore_ascii_case("block") {
            Some(Self::Block)
        } else {
            None
        }
    }
}

/// `?type=allow|block`. Kept as a string so a bad value gets a Pi-hole error
/// body instead of the extractor's plain-text rejection.
#[derive(Debug, Deserialize)]
pub struct ListTypeQuery {
    pub r#type: Option<String>,
}

/// Pi-hole v6 adlist/list entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeListEntry {
    pub address: String,
    pub comment: Option<String>,
    /// FTL group ids; the default group is 0.
    pub groups: Vec<i64>,
    pub enabled: bool,
    /// Database id, unique only within one list type.
    pub id: i64,
    /// Unix seconds.
    pub date_added: i64,
    /// Unix seconds.
    pub date_modified: i64,
    pub r#type: ListType,
    /// Unix seconds of the last successful download; 0 when never.
    pub date_updated: i64,
    /// Always 0: Ferrous does not count the domains of a list.
    pub number: u64,
    /// Always 0, as `number`.
    pub invalid_domains: u64,
    /// Always 0, as `number`.
    pub abp_entries: u64,
    /// FTL's list status: 1 once a download has succeeded, else 0 (unknown).
    pub status: i64,
}

/// Pi-hole v6 POST /api/lists request; the type comes from `?type=`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateListRequest {
    /// One list URL, or an array of them.
    pub address: Option<StringOrArray>,
    pub comment: Option<String>,
    /// FTL group ids; the default group when omitted.
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 PUT /api/lists/{list} request; the list comes from the path
/// and `?type=`. The list is replaced: an omitted `comment` is cleared and
/// `enabled` defaults to true, while omitted `groups` stay as they are.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateListRequest {
    pub comment: Option<String>,
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 lists response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListsResponse {
    pub lists: Vec<PiholeListEntry>,
}

/// Pi-hole v6 POST/PUT list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListsWriteResponse {
    pub lists: Vec<PiholeListEntry>,
    pub processed: Processed,
}
