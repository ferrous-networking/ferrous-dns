pub mod blocked_service_repository;
pub mod blocklist_source_repository;
pub mod client_repository;
pub(crate) mod client_row_mapper;
pub mod client_subnet_repository;
pub mod config_persistence;
pub mod config_repository;
pub mod custom_service_repository;
pub mod group_repository;
mod list_source_sql;
pub mod managed_domain_repository;
pub mod query_log_repository;
pub mod regex_filter_repository;
pub mod schedule_profile_repository;
pub mod sqlite_safe_search_config_repository;
pub mod whitelist_source_repository;

pub mod api_token_repository;
pub mod session_repository;
pub mod user_repository;

pub use api_token_repository::SqliteApiTokenRepository;
pub use blocked_service_repository::SqliteBlockedServiceRepository;
pub use blocklist_source_repository::SqliteBlocklistSourceRepository;
pub use client_repository::SqliteClientRepository;
pub use client_subnet_repository::SqliteClientSubnetRepository;
pub use config_persistence::TomlConfigFilePersistence;
pub use config_repository::TomlConfigRepository;
pub use custom_service_repository::SqliteCustomServiceRepository;
pub use group_repository::SqliteGroupRepository;
pub use managed_domain_repository::SqliteManagedDomainRepository;
pub use regex_filter_repository::SqliteRegexFilterRepository;
pub use schedule_profile_repository::SqliteScheduleProfileRepository;
pub use session_repository::SqliteSessionRepository;
pub use sqlite_safe_search_config_repository::SqliteSafeSearchConfigRepository;
pub use user_repository::SqliteUserRepository;
pub use whitelist_source_repository::SqliteWhitelistSourceRepository;

use chrono::{DateTime, Utc};
use ferrous_dns_domain::{DomainAction, DomainError};
use tracing::{error, warn};

/// Column format every repository writes timestamps in; SQLite's `datetime()` emits the same shape.
const SQL_TS_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

pub(crate) fn sql_ts(t: DateTime<Utc>) -> String {
    t.format(SQL_TS_FORMAT).to_string()
}

pub(crate) fn sql_now() -> String {
    sql_ts(Utc::now())
}

/// The instant `ms` before now; a window reaching past chrono's range saturates to
/// "everything" because windows come from unvalidated API floats (`?from=1e30`).
fn ms_ago(ms: i64) -> DateTime<Utc> {
    chrono::Duration::try_milliseconds(ms)
        .and_then(|d| Utc::now().checked_sub_signed(d))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn ms_ago_cutoff(ms: i64) -> String {
    sql_ts(ms_ago(ms))
}

pub(crate) fn hours_ago(hours: f32) -> DateTime<Utc> {
    ms_ago((hours * 3_600_000.0) as i64)
}

pub(crate) fn hours_ago_cutoff(hours: f32) -> String {
    sql_ts(hours_ago(hours))
}

pub(crate) fn seconds_ago_cutoff(seconds: i64) -> String {
    ms_ago_cutoff(seconds.saturating_mul(1000))
}

/// A Unix time as a cutoff, or `None` past chrono's range, where it bounds
/// nothing a stored row could hold.
pub(crate) fn unix_cutoff(seconds: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(seconds, 0).map(sql_ts)
}

/// `map_err` adapter: logs `ctx` with the sqlx error and yields `DomainError::DatabaseError`.
pub(crate) fn db_err(ctx: &'static str) -> impl FnOnce(sqlx::Error) -> DomainError {
    move |e| {
        error!(error = %e, "{ctx}");
        DomainError::DatabaseError(e.to_string())
    }
}

pub(crate) fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.is_unique_violation())
}

pub(crate) fn is_fk_violation(e: &sqlx::Error) -> bool {
    // `ON DELETE RESTRICT` fails with SQLITE_CONSTRAINT_TRIGGER (1811), which sqlx doesn't classify as FK.
    matches!(e, sqlx::Error::Database(db)
        if db.is_foreign_key_violation() || db.message() == "FOREIGN KEY constraint failed")
}

/// Reads a stored `action` column; an unknown value falls back to `Deny` so a corrupt row fails closed.
pub(crate) fn parse_db_action(action: &str) -> DomainAction {
    action.parse().unwrap_or_else(|_| {
        warn!(action, "Invalid domain action in DB, defaulting to Deny");
        DomainAction::Deny
    })
}
