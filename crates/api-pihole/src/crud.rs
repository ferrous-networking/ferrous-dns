//! Conventions shared by the Pi-hole v6 list endpoints (`/domains`,
//! `/groups`, `/clients`, `/lists`), following FTL's `api/list.c` and
//! `database/gravity-db.c`.

use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ferrous_dns_domain::DomainError;
use serde_json::json;

use crate::{
    dto::crud::{Processed, ProcessedError, ProcessedItem, StringOrArray},
    errors::{is_server_error, pihole_error_response, PiholeApiError},
    timestamp::parse_unix_epoch,
};

/// Ferrous's built-in default group.
pub(crate) const DEFAULT_GROUP_ID: i64 = 1;

/// FTL's Default group.
const FTL_DEFAULT_GROUP_ID: i64 = 0;

/// What FTL reports when a write hits a uniqueness constraint.
const ITEM_ALREADY_PRESENT: &str = "The item is already present";

pub(crate) const LIST_IMPRECISE: &str = "Invalid request: Specify list to modify more precisely";

/// A Ferrous group id as FTL numbers it: the default group is 0 there.
pub(crate) fn to_ftl_group_id(id: i64) -> i64 {
    if id == DEFAULT_GROUP_ID {
        FTL_DEFAULT_GROUP_ID
    } else {
        id
    }
}

/// An FTL group id as Ferrous numbers it. Ferrous ids start at 1, so the
/// two mappings are inverses.
pub(crate) fn from_ftl_group_id(id: i64) -> i64 {
    if id == FTL_DEFAULT_GROUP_ID {
        DEFAULT_GROUP_ID
    } else {
        id
    }
}

/// FTL group ids as Ferrous numbers them, for entries that keep several.
pub(crate) fn from_ftl_group_ids(ids: Vec<i64>) -> Vec<i64> {
    ids.into_iter().map(from_ftl_group_id).collect()
}

/// The group a write assigns. Ferrous keeps one group per entry, so only
/// the first of FTL's `groups` array is used.
pub(crate) fn first_group(groups: Option<&[i64]>) -> Option<i64> {
    groups
        .and_then(<[i64]>::first)
        .copied()
        .map(from_ftl_group_id)
}

/// A stored `date_*` column as Unix seconds; 0 when it is missing.
pub(crate) fn unix_seconds(ts: Option<&str>) -> i64 {
    ts.and_then(parse_unix_epoch).unwrap_or(0)
}

/// A stored comment as FTL sends it: always present, `null` when empty.
pub(crate) fn reply_comment(comment: Option<&Arc<str>>) -> Option<String> {
    comment.filter(|c| !c.is_empty()).map(|c| c.to_string())
}

/// A request comment as FTL stores it: an empty string is no comment.
pub(crate) fn request_comment(comment: Option<String>) -> Option<String> {
    comment.filter(|c| !c.is_empty())
}

/// A failed list request: an FTL error of its own, or a domain error.
pub enum CrudError {
    Reply {
        key: &'static str,
        message: &'static str,
        hint: Option<String>,
    },
    Domain(DomainError),
}

impl CrudError {
    pub(crate) fn bad_request(message: &'static str, hint: Option<String>) -> Self {
        Self::Reply {
            key: "bad_request",
            message,
            hint,
        }
    }

    pub(crate) fn uri_error(message: &'static str) -> Self {
        Self::Reply {
            key: "uri_error",
            message,
            hint: None,
        }
    }

    /// A delete the store refused; api_list_remove answers it this way.
    pub(crate) fn from_delete(err: DomainError) -> Self {
        if is_server_error(&err) {
            return Self::Domain(err);
        }
        Self::Reply {
            key: "database_error",
            message: "Could not remove entries from table",
            hint: Some(err.to_string()),
        }
    }
}

impl From<DomainError> for CrudError {
    fn from(err: DomainError) -> Self {
        Self::Domain(err)
    }
}

impl IntoResponse for CrudError {
    fn into_response(self) -> Response {
        match self {
            Self::Reply { key, message, hint } => {
                pihole_error_response(StatusCode::BAD_REQUEST, key, message, hint.as_deref())
            }
            Self::Domain(err) => PiholeApiError(err).into_response(),
        }
    }
}

/// The items of a POST, which FTL wants as a non-empty string or array;
/// `missing` is its message when there are none.
pub(crate) fn require_items(
    value: Option<StringOrArray>,
    missing: &'static str,
) -> Result<Vec<String>, CrudError> {
    let items = value.map(StringOrArray::into_items).unwrap_or_default();
    if items.is_empty() || items.iter().any(String::is_empty) {
        return Err(CrudError::bad_request(missing, None));
    }
    Ok(items)
}

/// Rejects what FTL never accepts in an item: line breaks anywhere, which
/// would reach the `Location` header, and blanks outside group names.
pub(crate) fn reject_unsafe_item(item: &str, blanks_allowed: bool) -> Result<(), CrudError> {
    if item.contains(['\r', '\n']) {
        return Err(CrudError::bad_request(
            "Newlines and carriage returns are not allowed in any input",
            Some(item.to_string()),
        ));
    }
    if !blanks_allowed && item.contains([' ', '\t']) {
        return Err(CrudError::bad_request(
            "Spaces and tabs are not allowed in domains and URLs",
            Some(item.to_string()),
        ));
    }
    Ok(())
}

/// Files the outcome of writing `item`. A client error lands in
/// `processed.errors` as FTL does with a failed row; a server error aborts
/// the request.
pub(crate) fn record(
    processed: &mut Processed,
    item: &str,
    result: Result<(), DomainError>,
) -> Result<(), DomainError> {
    let error = match result {
        Ok(()) => {
            processed.success.push(ProcessedItem {
                item: item.to_string(),
            });
            return Ok(());
        }
        Err(err) if is_server_error(&err) => return Err(err),
        Err(DomainError::AlreadyExists(_)) => ITEM_ALREADY_PRESENT.to_string(),
        Err(err) => err.to_string(),
    };
    processed.errors.push(ProcessedError {
        item: item.to_string(),
        error,
    });
    Ok(())
}

/// The status of a write reply: `success` when anything was written, and
/// FTL's `database_error` when every item failed.
pub(crate) fn write_status(
    processed: &Processed,
    success: StatusCode,
) -> Result<StatusCode, CrudError> {
    match processed.errors.last() {
        Some(last) if processed.success.is_empty() => Err(CrudError::Reply {
            key: "database_error",
            message: "Could not add to gravity database",
            hint: Some(last.error.clone()),
        }),
        _ => Ok(success),
    }
}

/// The reply to a delete: 204 when anything went, else 404 with the empty
/// object api_list_remove sends.
pub(crate) fn delete_reply(deleted: usize) -> Response {
    if deleted > 0 {
        return StatusCode::NO_CONTENT.into_response();
    }
    (StatusCode::NOT_FOUND, Json(json!({}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_ids_swap_only_the_default_group() {
        assert_eq!(to_ftl_group_id(1), 0);
        assert_eq!(to_ftl_group_id(7), 7);
        assert_eq!(from_ftl_group_id(0), 1);
        assert_eq!(from_ftl_group_id(7), 7);
    }

    #[test]
    fn only_the_first_group_is_assigned() {
        assert_eq!(first_group(Some(&[0, 5])), Some(1));
        assert_eq!(first_group(Some(&[])), None);
        assert_eq!(first_group(None), None);
    }

    #[test]
    fn missing_or_unparsable_dates_are_zero() {
        assert_eq!(unix_seconds(Some("2024-01-15 12:30:00")), 1_705_321_800);
        assert_eq!(unix_seconds(Some("garbage")), 0);
        assert_eq!(unix_seconds(None), 0);
    }

    #[test]
    fn every_item_failing_is_a_database_error() {
        let mut processed = Processed::default();
        record(
            &mut processed,
            "a",
            Err(DomainError::AlreadyExists("a".into())),
        )
        .expect("recorded");

        assert!(write_status(&processed, StatusCode::CREATED).is_err());

        record(&mut processed, "b", Ok(())).expect("recorded");
        assert_eq!(
            write_status(&processed, StatusCode::CREATED).ok(),
            Some(StatusCode::CREATED)
        );
        assert_eq!(processed.errors[0].error, ITEM_ALREADY_PRESENT);
    }
}
