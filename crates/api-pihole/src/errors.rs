use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ferrous_dns_domain::DomainError;
use serde_json::json;
use tracing::error;

/// Unified error type for Pi-hole compatible endpoints.
///
/// Maps `DomainError` variants to the Pi-hole v6 JSON error format:
/// `{ "error": { "key": "<key>", "message": "<message>" } }`.
#[derive(Debug)]
pub struct PiholeApiError(pub DomainError);

impl From<DomainError> for PiholeApiError {
    fn from(err: DomainError) -> Self {
        Self(err)
    }
}

impl IntoResponse for PiholeApiError {
    fn into_response(self) -> Response {
        let (status, key) = pihole_status_and_key(&self.0);
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            error!(error = %self.0, "Pi-hole API request failed");
            return pihole_error_response(status, key, "internal error");
        }
        pihole_error_response(status, key, &self.0.to_string())
    }
}

/// A Pi-hole v6 error body, for replies with no `DomainError` behind them.
pub(crate) fn pihole_error_response(status: StatusCode, key: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "key": key, "message": message } })),
    )
        .into_response()
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
        | DomainError::GroupHasNoSchedule(_)
        | DomainError::ApiTokenNotFound(_)
        | DomainError::UserNotFound(_) => (StatusCode::NOT_FOUND, "not_found"),

        DomainError::InvalidDomainName(_)
        | DomainError::InvalidIpAddress(_)
        | DomainError::InvalidCidr(_)
        | DomainError::InvalidSafeSearchEngine(_)
        | DomainError::InvalidTimeSlot(_)
        | DomainError::InvalidScheduleProfile(_)
        | DomainError::ProtectedGroupCannotBeDisabled
        | DomainError::ProtectedGroupCannotBeDeleted
        | DomainError::InvalidBlocklistSource(_)
        | DomainError::InvalidWhitelistSource(_)
        | DomainError::InvalidManagedDomain(_)
        | DomainError::InvalidRegexFilter(_)
        | DomainError::InvalidGroupName(_)
        | DomainError::InvalidInput(_)
        | DomainError::InvalidUsername(_)
        | DomainError::InvalidPassword(_)
        | DomainError::MfaNotConfigured
        | DomainError::WebauthnNotConfigured
        | DomainError::WebauthnError(_) => (StatusCode::BAD_REQUEST, "bad_request"),

        DomainError::DuplicateScheduleProfileName(_)
        | DomainError::BlockedServiceAlreadyExists(_)
        | DomainError::CustomServiceAlreadyExists(_)
        | DomainError::SubnetConflict(_)
        | DomainError::GroupHasAssignedClients(_)
        | DomainError::DuplicateApiTokenName(_)
        | DomainError::DuplicateUsername(_)
        | DomainError::PasswordAlreadyConfigured
        | DomainError::MfaAlreadyEnabled
        | DomainError::AlreadyExists(_) => (StatusCode::CONFLICT, "already_exists"),

        DomainError::AuthRequired
        | DomainError::SessionNotFound
        | DomainError::InvalidCredentials
        | DomainError::InvalidMfaCode
        | DomainError::MfaChallengeExpired => (StatusCode::UNAUTHORIZED, "unauthorized"),

        DomainError::ProtectedUser => (StatusCode::FORBIDDEN, "forbidden"),

        DomainError::RateLimited
        | DomainError::DnsRateLimited
        | DomainError::DnsRateLimitedSlip => (StatusCode::TOO_MANY_REQUESTS, "rate_limiting"),

        DomainError::DnssecValidationFailed(_)
        | DomainError::InsecureDelegation
        | DomainError::DnssecBogus
        | DomainError::DnssecIndeterminate
        | DomainError::InvalidDnsResponse(_)
        | DomainError::DatabaseError(_)
        | DomainError::IoError(_)
        | DomainError::Blocked
        | DomainError::NxDomain
        | DomainError::LocalNxDomain
        | DomainError::QueryTimeout
        | DomainError::DnsTunnelingDetected
        | DomainError::DgaDomainDetected
        | DomainError::DnsCookieInvalid
        | DomainError::FilteredQuery(_)
        | DomainError::BlockFilterFetchError(_)
        | DomainError::BlockFilterCompileError(_)
        | DomainError::TransportTimeout { .. }
        | DomainError::TransportConnectionRefused { .. }
        | DomainError::TransportConnectionReset { .. }
        | DomainError::ConfigError(_)
        | DomainError::TransportNoHealthyServers
        | DomainError::TransportAllServersUnreachable
        | DomainError::UpstreamCapacityExhausted
        | DomainError::SpoofedResponse { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use serde_json::Value;

    async fn render(err: DomainError) -> (StatusCode, Value) {
        let resp = PiholeApiError(err).into_response();
        let status = resp.status();
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        (status, serde_json::from_slice(&body).expect("json"))
    }

    #[tokio::test]
    async fn internal_errors_hide_their_text_from_clients() {
        let (status, body) = render(DomainError::DatabaseError(
            "no such table: /var/lib/ferrous/secret.db".into(),
        ))
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body,
            json!({ "error": { "key": "server_error", "message": "internal error" } })
        );
    }

    #[tokio::test]
    async fn client_errors_keep_their_message() {
        let (status, body) = render(DomainError::ClientNotFound("10.0.0.9".into())).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["key"], "not_found");
        assert_eq!(
            body["error"]["message"],
            DomainError::ClientNotFound("10.0.0.9".into()).to_string()
        );
    }

    #[tokio::test]
    async fn expired_mfa_challenge_is_unauthorized_not_server_error() {
        let (status, body) = render(DomainError::MfaChallengeExpired).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["key"], "unauthorized");
    }

    #[tokio::test]
    async fn invalid_input_is_bad_request_not_server_error() {
        let (status, body) = render(DomainError::InvalidInput("bad record type".into())).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["key"], "bad_request");
    }
}
