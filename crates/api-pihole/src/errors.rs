use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ferrous_dns_domain::DomainError;
use serde_json::json;
use thiserror::Error;

/// Unified error type for Pi-hole compatible endpoints.
///
/// Maps `DomainError` variants to the Pi-hole v6 JSON error format:
/// `{ "error": { "key": "<key>", "message": "<message>" } }`.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct PiholeApiError(#[from] pub DomainError);

impl IntoResponse for PiholeApiError {
    fn into_response(self) -> Response {
        let (status, key) = pihole_status_and_key(&self.0);
        let message = self.0.to_string();
        (
            status,
            Json(json!({ "error": { "key": key, "message": message } })),
        )
            .into_response()
    }
}

fn pihole_status_and_key(err: &DomainError) -> (StatusCode, &'static str) {
    match err {
        DomainError::NotFound(_)
        | DomainError::BlocklistSourceNotFound(_)
        | DomainError::WhitelistSourceNotFound(_)
        | DomainError::ManagedDomainNotFound(_)
        | DomainError::RegexFilterNotFound(_)
        | DomainError::CustomServiceNotFound(_)
        | DomainError::ClientNotFound(_)
        | DomainError::SubnetNotFound(_)
        | DomainError::ServiceNotFoundInCatalog(_)
        | DomainError::ScheduleProfileNotFound(_)
        | DomainError::TimeSlotNotFound(_)
        | DomainError::GroupNotFound(_)
        | DomainError::GroupHasNoSchedule(_) => (StatusCode::NOT_FOUND, "not_found"),

        DomainError::InvalidDomainName(_)
        | DomainError::InvalidIpAddress(_)
        | DomainError::InvalidCidr(_)
        | DomainError::InvalidSafeSearchEngine(_)
        | DomainError::InvalidTimeSlot(_)
        | DomainError::InvalidTimezone(_)
        | DomainError::InvalidScheduleProfile(_)
        | DomainError::ProtectedGroupCannotBeDisabled
        | DomainError::ProtectedGroupCannotBeDeleted => {
            (StatusCode::UNPROCESSABLE_ENTITY, "bad_request")
        }

        DomainError::InvalidBlocklistSource(_)
        | DomainError::InvalidWhitelistSource(_)
        | DomainError::InvalidManagedDomain(_)
        | DomainError::InvalidRegexFilter(_)
        | DomainError::InvalidGroupName(_) => (StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),

        DomainError::DuplicateScheduleProfileName(_)
        | DomainError::BlockedServiceAlreadyExists(_)
        | DomainError::CustomServiceAlreadyExists(_)
        | DomainError::SubnetConflict(_)
        | DomainError::GroupHasAssignedClients(_) => (StatusCode::CONFLICT, "already_exists"),

        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}
