use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::dto::crud::{Processed, StringOrArray};

/// Pi-hole v6 group entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeGroupEntry {
    pub name: String,
    pub comment: Option<String>,
    pub enabled: bool,
    /// FTL group id; the default group is 0.
    pub id: i64,
    /// Unix seconds.
    pub date_added: i64,
    /// Unix seconds.
    pub date_modified: i64,
}

/// Pi-hole v6 POST /api/groups request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: Option<StringOrArray>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 PUT /api/groups/:name request. The group is replaced: an
/// omitted `comment` is cleared and `enabled` defaults to true.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateGroupRequest {
    /// Renames the group named in the URI.
    pub name: Option<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 groups list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct GroupsResponse {
    pub groups: Vec<PiholeGroupEntry>,
}

/// Pi-hole v6 POST/PUT group response.
#[derive(Debug, Serialize, ToSchema)]
pub struct GroupsWriteResponse {
    pub groups: Vec<PiholeGroupEntry>,
    pub processed: Processed,
}
