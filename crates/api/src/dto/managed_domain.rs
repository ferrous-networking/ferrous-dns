use ferrous_dns_application::ports::CreateManyOutcome;
use ferrous_dns_application::use_cases::BulkEntryResult;
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct ManagedDomainQuery {
    /// Domains per page, 1 to 1000; default 100.
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    /// Keeps only the domains whose domain or name contains this text, ignoring
    /// ASCII case; `total` then counts the matches. Blank means no filter.
    #[serde(default)]
    pub search: Option<String>,
}

fn default_limit() -> u32 {
    100
}

#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedManagedDomains {
    pub data: Vec<ManagedDomainResponse>,
    /// Every managed domain, across all pages.
    pub total: u64,
    /// Page size applied: the requested `limit`, clamped to 1..=1000.
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ManagedDomainResponse {
    pub id: i64,
    pub name: String,
    pub domain: String,
    #[schema(value_type = String)]
    pub action: &'static str,
    pub group_id: i64,
    pub comment: Option<String>,
    pub enabled: bool,
    pub service_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// When the rule stops applying and is removed, in UTC; `null` for a rule
    /// that never expires.
    pub expires_at: Option<String>,
}

impl ManagedDomainResponse {
    pub fn from_domain(d: ManagedDomain) -> Self {
        Self {
            id: d.id.unwrap_or(0),
            name: d.name.to_string(),
            domain: d.domain.to_string(),
            action: d.action.to_str(),
            group_id: d.group_id,
            comment: d.comment.as_ref().map(|s| s.to_string()),
            enabled: d.enabled,
            service_id: d.service_id.as_ref().map(|s| s.to_string()),
            created_at: d.created_at,
            updated_at: d.updated_at,
            expires_at: d.expires_at,
        }
    }
}

/// Parses a request `action` field shared by managed domains and regex filters.
pub fn parse_action(value: &str) -> Result<DomainAction, DomainError> {
    value.parse()
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateManagedDomainRequest {
    pub name: String,
    pub domain: String,
    pub action: String,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
    /// Removes the rule this many seconds after it is created, 60 to 2592000
    /// (30 days). Absent keeps it until it is deleted.
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateManagedDomainRequest {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub action: Option<String>,
    pub group_id: Option<i64>,
    /// Absent keeps the comment; `null` clears it.
    #[serde(default, deserialize_with = "crate::dto::source_common::double_option")]
    pub comment: Option<Option<String>>,
    pub enabled: Option<bool>,
}

/// Domains to add as permanent rules that share an action, a group, a
/// comment and an enabled state.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BulkCreateManagedDomainsRequest {
    /// 1 to 10000 exact domains or `*.` wildcards. Each becomes a rule named
    /// after its domain, or `<domain> (<action>)` when the group already has
    /// a rule by that name.
    pub domains: Vec<String>,
    pub action: String,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BulkEntryStatus {
    /// A rule was created.
    Added,
    /// The group already has a permanent rule for the domain with the same
    /// action and enabled state (a blocked service's rule does not count), or
    /// every name the rule could take is used.
    Existing,
    /// The domain is not valid; `error` says why.
    Invalid,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkEntryResponse {
    /// The domain as stored: trimmed and lowercased.
    pub domain: String,
    pub status: BulkEntryStatus,
    /// Why the entry is `invalid`, or the name clash that kept it `existing`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BulkEntryResponse {
    pub fn from_result(result: BulkEntryResult) -> Self {
        let (status, error) = match result.outcome {
            Ok(CreateManyOutcome::Created(_)) => (BulkEntryStatus::Added, None),
            Ok(CreateManyOutcome::AlreadyPresent) => (BulkEntryStatus::Existing, None),
            Ok(CreateManyOutcome::NameTaken) => (
                BulkEntryStatus::Existing,
                Some(format!(
                    "Another rule in this group is named '{}'",
                    result.domain
                )),
            ),
            Err(e) => (BulkEntryStatus::Invalid, Some(e.to_string())),
        };
        Self {
            domain: result.domain,
            status,
            error,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkCreateManagedDomainsResponse {
    /// One result per requested domain, in request order.
    pub results: Vec<BulkEntryResponse>,
}
