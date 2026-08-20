//! OpenAPI document for the native Ferrous DNS REST API.
//!
//! This module defines the [`ApiDoc`] type that aggregates every handler
//! annotated with `#[utoipa::path]` plus all DTO schemas. The router itself
//! is assembled in [`crate::routes`] using `utoipa-axum`'s `OpenApiRouter`;
//! `ApiDoc` is the static counterpart consumed by tooling that needs a
//! standalone `OpenApi` value (e.g. snapshot tests).
//!
//! Two security schemes are advertised:
//!   * `session_cookie` — `ferrous_session` cookie (browser sessions)
//!   * `api_key` — `X-Api-Key` header (machine-to-machine)
//!
//! Public endpoints (login, logout, setup, status, health) declare
//! `security()` explicitly to opt out.

use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};

use crate::dto;

/// Adds the cookie and API-key security schemes to the generated spec.
pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);

        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("ferrous_session"))),
        );
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Api-Key"))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ferrous DNS API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Native REST API for Ferrous DNS — manages blocking, clients, groups, \
                       DNS cache, schedules, services and authentication. \
                       Authenticate via the `ferrous_session` cookie or the `X-Api-Key` header."
    ),
    tags(
        (name = "auth", description = "Authentication, sessions and password management"),
        (name = "users", description = "Local user accounts and roles"),
        (name = "api_tokens", description = "Machine-to-machine API keys"),
        (name = "dashboard", description = "Aggregated dashboard payload"),
        (name = "stats", description = "Query statistics and timelines"),
        (name = "queries", description = "Recent DNS query log"),
        (name = "dnssec", description = "DNSSEC validation statistics"),
        (name = "cache", description = "DNS cache statistics and metrics"),
        (name = "clients", description = "Client inventory and group assignment"),
        (name = "groups", description = "Client groups"),
        (name = "client_subnets", description = "CIDR-based group mapping"),
        (name = "blocking", description = "Blocklist, whitelist, managed domains and regex filters"),
        (name = "blocklist_sources", description = "External blocklist sources"),
        (name = "whitelist_sources", description = "External whitelist sources"),
        (name = "services", description = "Service catalog and per-group service blocking"),
        (name = "custom_services", description = "User-defined service catalog entries"),
        (name = "safe_search", description = "Safe Search enforcement per group"),
        (name = "schedules", description = "Time-based blocking profiles"),
        (name = "local_records", description = "Locally served DNS records"),
        (name = "config", description = "Runtime configuration"),
        (name = "system", description = "Host, hostname and upstream health"),
        (name = "tls", description = "Web TLS certificate management"),
        (name = "backup", description = "Configuration export/import"),
        (name = "block_filter", description = "Block filter engine status"),
    ),
    modifiers(&SecurityAddon),
    components(schemas(
        // auth
        dto::auth::LoginRequest,
        dto::auth::LoginResponse,
        dto::auth::SetupPasswordRequest,
        dto::auth::ChangePasswordRequest,
        dto::auth::AuthStatusResponse,
        dto::auth::SessionResponse,
        // mfa / 2fa
        dto::auth::VerifyMfaRequest,
        dto::auth::SetupTotpResponse,
        dto::auth::ConfirmTotpRequest,
        dto::auth::RecoveryCodesResponse,
        dto::auth::DisableMfaRequest,
        dto::auth::PasskeyResponse,
        dto::auth::MfaStatusResponse,
        dto::auth::RegisterPasskeyStartRequest,
        dto::auth::WebauthnRegisterStartResponse,
        dto::auth::RegisterPasskeyFinishRequest,
        dto::auth::WebauthnAuthStartRequest,
        dto::auth::WebauthnAuthFinishRequest,
        dto::auth::DiscoverableStartResponse,
        dto::auth::DiscoverableFinishRequest,
        // api tokens
        dto::api_token::CreateApiTokenRequest,
        dto::api_token::UpdateApiTokenRequest,
        dto::api_token::CreatedApiTokenResponse,
        dto::api_token::ApiTokenResponse,
        // users
        dto::user::CreateUserRequest,
        dto::user::UserResponse,
        // backup
        dto::backup::ImportSummaryResponse,
        dto::backup::ImportSummaryDto,
        // block filter
        dto::block_filter::BlockFilterStatsResponse,
        dto::block_filter::FilterTestRequest,
        dto::block_filter::FilterTestResponse,
        dto::block_filter::FilterMatchDto,
        dto::block_filter::BacktestRequestDto,
        dto::block_filter::BacktestResponse,
        dto::block_filter::AffectedDomainDto,
        // services
        dto::ServiceDefinitionResponse,
        dto::BlockedServiceResponse,
        dto::BlockServiceRequest,
        dto::CustomServiceResponse,
        dto::CreateCustomServiceRequest,
        dto::UpdateCustomServiceRequest,
        // blocklist
        dto::BlocklistResponse,
        dto::PaginatedBlocklist,
        dto::BlocklistSourceResponse,
        dto::CreateBlocklistSourceRequest,
        dto::UpdateBlocklistSourceRequest,
        // whitelist
        dto::WhitelistResponse,
        dto::WhitelistSourceResponse,
        dto::CreateWhitelistSourceRequest,
        dto::UpdateWhitelistSourceRequest,
        // managed domains
        dto::ManagedDomainResponse,
        dto::PaginatedManagedDomains,
        dto::CreateManagedDomainRequest,
        dto::UpdateManagedDomainRequest,
        // regex filters
        dto::RegexFilterResponse,
        dto::CreateRegexFilterRequest,
        dto::UpdateRegexFilterRequest,
        // cache
        dto::CacheStatsResponse,
        dto::CacheMetricsResponse,
        dto::CacheEntryResponse,
        dto::PaginatedCacheEntries,
        // clients
        dto::ClientResponse,
        dto::ClientStatsResponse,
        dto::UpdateClientRequest,
        dto::ClientSubnetResponse,
        dto::CreateClientSubnetRequest,
        dto::CreateManualClientRequest,
        // groups
        dto::GroupResponse,
        dto::CreateGroupRequest,
        dto::UpdateGroupRequest,
        dto::AssignGroupRequest,
        // config
        dto::config::ConfigResponse,
        dto::config::AuthConfigResponse,
        dto::config::ServerConfigResponse,
        dto::config::WebTlsConfigResponse,
        dto::config::DnsConfigResponse,
        dto::config::RateLimitConfigResponse,
        dto::config::UpstreamPoolResponse,
        dto::config::HealthCheckResponse,
        dto::config::BlockingConfigResponse,
        dto::config::LoggingConfigResponse,
        dto::config::DatabaseConfigResponse,
        dto::config::UpdateConfigRequest,
        dto::config::AuthConfigUpdate,
        dto::config::ServerConfigUpdate,
        dto::config::WebTlsConfigUpdate,
        dto::config::PoolUpdate,
        dto::config::DnsConfigUpdate,
        dto::config::RateLimitConfigUpdate,
        dto::config::BlockingConfigUpdate,
        dto::config::SettingsDto,
        dto::config::SettingsUpdateResponse,
        // dashboard / stats
        dto::DashboardResponse,
        dto::TopBlockedDomain,
        dto::TopClient,
        dto::StatsResponse,
        dto::TypeDistribution,
        dto::TopType,
        dto::QueryRateResponse,
        // queries
        dto::QueryResponse,
        dto::PaginatedQueries,
        // dnssec
        dto::DnssecStatsResponse,
        // timeline
        dto::TimelineBucket,
        dto::TimelineResponse,
        // safe search
        dto::SafeSearchConfigResponse,
        dto::ToggleSafeSearchRequest,
        // schedule
        dto::schedule::CreateScheduleProfileRequest,
        dto::schedule::UpdateScheduleProfileRequest,
        dto::schedule::AddTimeSlotRequest,
        dto::schedule::AssignProfileRequest,
        dto::schedule::ScheduleProfileResponse,
        dto::schedule::TimeSlotResponse,
        dto::schedule::ScheduleProfileWithSlotsResponse,
        dto::schedule::GroupScheduleResponse,
        // local records
        dto::LocalRecordDto,
        dto::CreateLocalRecordRequest,
        dto::local_record::UpdateLocalRecordRequest,
        // misc
        dto::HostnameResponse,
        dto::SystemInfoResponse,
        dto::TlsStatusResponse,
        dto::TlsUploadResponse,
    )),
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_spec_serializes_with_security_schemes() {
        let spec = ApiDoc::openapi();
        let json = serde_json::to_value(&spec).expect("spec must serialize");

        assert_eq!(json["info"]["title"], "Ferrous DNS API");
        assert_eq!(json["info"]["version"], env!("CARGO_PKG_VERSION"));

        let schemes = &json["components"]["securitySchemes"];
        assert!(schemes["session_cookie"].is_object());
        assert!(schemes["api_key"].is_object());
    }

    #[test]
    fn openapi_spec_contains_core_schemas() {
        let spec = ApiDoc::openapi();
        let json = serde_json::to_value(&spec).expect("spec must serialize");
        let schemas = &json["components"]["schemas"];

        for required in ["LoginRequest", "QueryResponse", "DashboardResponse"] {
            assert!(!schemas[required].is_null(), "missing schema {required}");
        }
    }
}
