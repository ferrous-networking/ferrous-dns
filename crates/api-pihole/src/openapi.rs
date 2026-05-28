//! OpenAPI 3.x specification for the Pi-hole v6 compatible API.
//!
//! Best-effort implementation aligned with the public Pi-hole v6 surface
//! documented at <https://pi-hole.net/docs/api>. Divergences are tracked
//! in the project documentation.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::dto;

/// OpenAPI document describing every Pi-hole compatible route.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Pi-hole v6 Compatible API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Pi-hole v6 compatibility layer. Best-effort implementation aligned with pi-hole.net/docs/api — see project docs for divergences."
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "pihole:auth", description = "Session authentication"),
        (name = "pihole:stats", description = "Aggregated statistics"),
        (name = "pihole:queries", description = "Query log access"),
        (name = "pihole:dns", description = "DNS blocking control"),
        (name = "pihole:domains", description = "Managed and regex domains"),
        (name = "pihole:lists", description = "Blocklist and allowlist sources"),
        (name = "pihole:groups", description = "Client groups"),
        (name = "pihole:clients", description = "Client management"),
        (name = "pihole:info", description = "Runtime, host and database info"),
        (name = "pihole:action", description = "Administrative actions"),
        (name = "pihole:history", description = "Historic time-series data"),
        (name = "pihole:search", description = "Filter evaluation")
    ),
    paths(
        crate::handlers::auth::get_session,
        crate::handlers::auth::login,
        crate::handlers::auth::logout,
        crate::handlers::stats::get_summary,
        crate::handlers::stats::get_history,
        crate::handlers::stats::get_top_blocked,
        crate::handlers::stats::get_top_clients,
        crate::handlers::stats::get_query_types,
        crate::handlers::stats::get_top_domains,
        crate::handlers::stats::get_upstreams,
        crate::handlers::stats::get_recent_blocked,
        crate::handlers::history::get_history_clients,
        crate::handlers::queries::get_queries,
        crate::handlers::queries::get_suggestions,
        crate::handlers::search::search_domain,
        crate::handlers::dns::get_blocking,
        crate::handlers::dns::set_blocking,
        crate::handlers::domains::list_all,
        crate::handlers::domains::list_by_type,
        crate::handlers::domains::list_by_type_kind,
        crate::handlers::domains::create_domain,
        crate::handlers::domains::update_domain,
        crate::handlers::domains::delete_domain,
        crate::handlers::domains::batch_delete,
        crate::handlers::lists::list_all,
        crate::handlers::lists::create_list,
        crate::handlers::lists::get_by_id,
        crate::handlers::lists::update_list,
        crate::handlers::lists::delete_list,
        crate::handlers::lists::batch_delete,
        crate::handlers::groups::list_all,
        crate::handlers::groups::create_group,
        crate::handlers::groups::get_by_name,
        crate::handlers::groups::update_group,
        crate::handlers::groups::delete_group,
        crate::handlers::groups::batch_delete,
        crate::handlers::clients::list_all,
        crate::handlers::clients::create_client,
        crate::handlers::clients::update_client,
        crate::handlers::clients::delete_client,
        crate::handlers::clients::suggestions,
        crate::handlers::clients::batch_delete,
        crate::handlers::info::get_version,
        crate::handlers::info::get_ftl_info,
        crate::handlers::info::get_system_info,
        crate::handlers::info::get_host_info,
        crate::handlers::info::get_database_info,
        crate::handlers::action::gravity,
        crate::handlers::action::restartdns,
        crate::handlers::action::flush_logs,
    ),
    components(schemas(
        dto::action::ActionResponse,
        dto::auth::LoginRequest,
        dto::auth::SessionInfo,
        dto::auth::AuthResponse,
        dto::clients::PiholeClientEntry,
        dto::clients::CreateClientRequest,
        dto::clients::UpdateClientRequest,
        dto::clients::ClientsResponse,
        dto::clients::ClientSuggestionsResponse,
        dto::dns::BlockingStatusResponse,
        dto::dns::SetBlockingRequest,
        dto::domains::PiholeDomainEntry,
        dto::domains::CreateDomainRequest,
        dto::domains::BatchDeleteRequest,
        dto::domains::DomainsListResponse,
        dto::groups::PiholeGroupEntry,
        dto::groups::CreateGroupRequest,
        dto::groups::UpdateGroupRequest,
        dto::groups::GroupsResponse,
        dto::history::HistoryClientsResponse,
        dto::history::ClientHistoryEntry,
        dto::info::VersionResponse,
        dto::info::FtlInfoResponse,
        dto::info::FtlDatabaseInfo,
        dto::info::SystemInfoResponse,
        dto::info::MemoryInfo,
        dto::info::DiskInfo,
        dto::info::HostInfoResponse,
        dto::info::DatabaseInfoResponse,
        dto::lists::PiholeListEntry,
        dto::lists::CreateListRequest,
        dto::lists::ListsResponse,
        dto::queries::QueriesResponse,
        dto::queries::PiholeClientRef,
        dto::queries::PiholeReply,
        dto::queries::PiholeEde,
        dto::queries::PiholeQueryEntry,
        dto::queries::SuggestionsResponse,
        dto::search::SearchResponse,
        dto::search::SearchResult,
        dto::stats::SummaryResponse,
        dto::stats::QuerySummary,
        dto::stats::ClientSummary,
        dto::stats::GravitySummary,
        dto::stats::HistoryResponse,
        dto::stats::HistoryBucket,
        dto::stats::TopDomainsResponse,
        dto::stats::TopDomainEntry,
        dto::stats::TopClientsResponse,
        dto::stats::TopClientEntry,
        dto::stats::QueryTypesResponse,
        dto::stats::RecentBlockedResponse,
        dto::upstreams::UpstreamsResponse,
    ))
)]
pub struct PiholeApiDoc;

/// Adds the Pi-hole v6 session header (`X-FTL-SID`) as a reusable security scheme.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);
        components.add_security_scheme(
            "session_id",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-FTL-SID"))),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_spec_serializes_with_session_security() {
        let spec = PiholeApiDoc::openapi();
        let json = serde_json::to_value(&spec).expect("spec must serialize");

        assert_eq!(json["info"]["title"], "Pi-hole v6 Compatible API");
        assert_eq!(json["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(json["components"]["securitySchemes"]["session_id"].is_object());
    }

    #[test]
    fn openapi_spec_contains_critical_paths() {
        let spec = PiholeApiDoc::openapi();
        let paths: Vec<&str> = spec.paths.paths.keys().map(|s| s.as_str()).collect();

        for required in ["/auth", "/stats/summary", "/dns/blocking"] {
            assert!(
                paths.contains(&required),
                "missing path {required}; available: {paths:?}"
            );
        }
    }
}
