use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ferrous_dns_domain::DomainError;
use serde_json::json;
use tracing::error;

pub struct ApiError(pub DomainError);

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        Self(err)
    }
}

fn status_code(err: &DomainError) -> StatusCode {
    match err {
        DomainError::NotFound(_)
        | DomainError::GroupNotFound(_)
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
        | DomainError::GroupHasNoSchedule(_)
        | DomainError::ApiTokenNotFound(_)
        | DomainError::UserNotFound(_)
        | DomainError::SessionNotFound => StatusCode::NOT_FOUND,

        DomainError::InvalidCredentials
        | DomainError::AuthRequired
        | DomainError::InvalidMfaCode
        | DomainError::MfaChallengeExpired => StatusCode::UNAUTHORIZED,

        DomainError::ProtectedUser | DomainError::Blocked | DomainError::DnsTunnelingDetected => {
            StatusCode::FORBIDDEN
        }

        DomainError::RateLimited
        | DomainError::DnsRateLimited
        | DomainError::DnsRateLimitedSlip => StatusCode::TOO_MANY_REQUESTS,

        DomainError::MfaAlreadyEnabled
        | DomainError::DuplicateApiTokenName(_)
        | DomainError::DuplicateUsername(_)
        | DomainError::PasswordAlreadyConfigured
        | DomainError::DuplicateScheduleProfileName(_)
        | DomainError::BlockedServiceAlreadyExists(_)
        | DomainError::CustomServiceAlreadyExists(_)
        | DomainError::SubnetConflict(_)
        | DomainError::GroupHasAssignedClients(_)
        | DomainError::AlreadyExists(_) => StatusCode::CONFLICT,

        DomainError::MfaNotConfigured
        | DomainError::WebauthnNotConfigured
        | DomainError::WebauthnError(_)
        | DomainError::InvalidUsername(_)
        | DomainError::InvalidPassword(_)
        | DomainError::InvalidInput(_)
        | DomainError::InvalidDomainName(_)
        | DomainError::InvalidIpAddress(_)
        | DomainError::InvalidCidr(_)
        | DomainError::InvalidSafeSearchEngine(_)
        | DomainError::InvalidTimeSlot(_)
        | DomainError::InvalidScheduleProfile(_)
        | DomainError::InvalidBlocklistSource(_)
        | DomainError::InvalidWhitelistSource(_)
        | DomainError::InvalidManagedDomain(_)
        | DomainError::InvalidRegexFilter(_)
        | DomainError::InvalidGroupName(_)
        | DomainError::ProtectedGroupCannotBeDisabled
        | DomainError::ProtectedGroupCannotBeDeleted => StatusCode::BAD_REQUEST,

        DomainError::DnssecValidationFailed(_)
        | DomainError::InsecureDelegation
        | DomainError::DnssecBogus
        | DomainError::InvalidDnsResponse(_)
        | DomainError::DatabaseError(_)
        | DomainError::IoError(_)
        | DomainError::NxDomain
        | DomainError::LocalNxDomain
        | DomainError::QueryTimeout
        | DomainError::DgaDomainDetected
        | DomainError::DnsCookieInvalid
        | DomainError::FilteredQuery(_)
        | DomainError::BlockFilterFetchError(_)
        | DomainError::BlockFilterCompileError(_)
        | DomainError::TransportTimeout { .. }
        | DomainError::TransportConnectionRefused { .. }
        | DomainError::TransportConnectionReset { .. }
        | DomainError::TransportNoHealthyServers
        | DomainError::TransportAllServersUnreachable
        | DomainError::UpstreamCapacityExhausted
        | DomainError::SpoofedResponse { .. }
        | DomainError::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = status_code(&self.0);
        let message = match self.0 {
            DomainError::Blocked => "blocked".to_string(),
            // Internal details stay in the log, never in the response body.
            err if status.is_server_error() => {
                error!(error = %err, "request failed with an internal error");
                "internal error".to_string()
            }
            err => err.to_string(),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
