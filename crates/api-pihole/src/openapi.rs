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
    components(schemas(
        dto::action::ActionResponse,
        dto::auth::LoginRequest,
        dto::auth::TotpCode,
        dto::auth::SessionInfo,
        dto::auth::AuthResponse,
        dto::clients::PiholeClientEntry,
        dto::clients::CreateClientRequest,
        dto::clients::UpdateClientRequest,
        dto::clients::ClientsResponse,
        dto::clients::ClientSuggestionsResponse,
        dto::dns::BlockingStatus,
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
        dto::info::LoginInfoResponse,
        dto::info::VersionResponse,
        dto::info::VersionComponents,
        dto::info::ComponentVersion,
        dto::info::FtlComponentVersion,
        dto::info::LocalVersion,
        dto::info::FtlLocalVersion,
        dto::info::RemoteVersion,
        dto::info::DockerVersion,
        dto::info::FtlInfoResponse,
        dto::info::FtlDatabaseInfo,
        dto::info::SystemInfoResponse,
        dto::info::MemoryInfo,
        dto::info::DiskInfo,
        dto::info::HostInfoResponse,
        dto::info::DatabaseInfoResponse,
        dto::lists::ListType,
        dto::lists::PiholeListEntry,
        dto::lists::CreateListRequest,
        dto::lists::UpdateListRequest,
        dto::lists::ListBatchDeleteItem,
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
        dto::stats::QueryTypeCounts,
        dto::stats::QueryStatusCounts,
        dto::stats::ReplyTypeCounts,
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
        dto::upstreams::UpstreamEntry,
        dto::upstreams::UpstreamStatistics,
    ))
)]
pub(crate) struct PiholeApiDoc;

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
