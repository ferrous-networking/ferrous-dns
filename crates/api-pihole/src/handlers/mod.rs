pub mod action;
pub mod auth;
pub mod clients;
pub mod dns;
pub mod domains;
pub mod endpoints;
pub mod groups;
pub mod history;
pub mod info;
pub mod lists;
pub mod padd;
pub mod queries;
pub mod search;
pub mod stats;

use ferrous_dns_domain::DomainError;

/// Persisted records always carry an id; a missing one is a repository bug.
pub(crate) fn require_id(id: Option<i64>, what: &'static str) -> Result<i64, DomainError> {
    id.ok_or_else(|| DomainError::DatabaseError(format!("{what} missing id")))
}
