use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ferrous_dns_domain::DomainError;
use serde_json::json;

pub struct ApiError(pub DomainError);

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        Self(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self.0 {
            DomainError::NotFound(_)
            | DomainError::BlocklistSourceNotFound(_)
            | DomainError::WhitelistSourceNotFound(_)
            | DomainError::ManagedDomainNotFound(_)
            | DomainError::RegexFilterNotFound(_)
            | DomainError::CustomServiceNotFound(_)
            | DomainError::ClientNotFound(_)
            | DomainError::SubnetNotFound(_)
            | DomainError::ServiceNotFoundInCatalog(_) => {
                (StatusCode::NOT_FOUND, self.0.to_string())
            }

            DomainError::Blocked => (StatusCode::FORBIDDEN, "blocked".to_string()),

            DomainError::InvalidDomainName(_)
            | DomainError::InvalidIpAddress(_)
            | DomainError::InvalidCidr(_)
            | DomainError::ProtectedGroupCannotBeDisabled
            | DomainError::ProtectedGroupCannotBeDeleted
            | DomainError::GroupNotFound(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),

            DomainError::InvalidBlocklistSource(_)
            | DomainError::InvalidWhitelistSource(_)
            | DomainError::InvalidManagedDomain(_)
            | DomainError::InvalidRegexFilter(_)
            | DomainError::InvalidGroupName(_)
            | DomainError::BlockedServiceAlreadyExists(_)
            | DomainError::CustomServiceAlreadyExists(_)
            | DomainError::SubnetConflict(_)
            | DomainError::GroupHasAssignedClients(_) => (StatusCode::CONFLICT, self.0.to_string()),

            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
