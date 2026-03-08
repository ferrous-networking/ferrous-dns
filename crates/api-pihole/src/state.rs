use ferrous_dns_application::ports::{BlockFilterEnginePort, UpstreamHealthPort};
use ferrous_dns_application::use_cases::{AssignClientGroupUseCase, GetTopAllowedDomainsUseCase};
use ferrous_dns_application::use_cases::{
    CleanupOldQueryLogsUseCase, CreateBlocklistSourceUseCase, CreateGroupUseCase,
    CreateManagedDomainUseCase, CreateManualClientUseCase, CreateRegexFilterUseCase,
    CreateWhitelistSourceUseCase, DeleteBlocklistSourceUseCase, DeleteClientUseCase,
    DeleteGroupUseCase, DeleteManagedDomainUseCase, DeleteRegexFilterUseCase,
    DeleteWhitelistSourceUseCase, GetBlockFilterStatsUseCase, GetBlocklistSourcesUseCase,
    GetCacheStatsUseCase, GetClientsUseCase, GetGroupsUseCase, GetManagedDomainsUseCase,
    GetQueryStatsUseCase, GetRecentQueriesUseCase, GetRegexFiltersUseCase, GetTimelineUseCase,
    GetTopBlockedDomainsUseCase, GetTopClientsUseCase, GetWhitelistSourcesUseCase,
    UpdateBlocklistSourceUseCase, UpdateClientUseCase, UpdateGroupUseCase,
    UpdateManagedDomainUseCase, UpdateRegexFilterUseCase, UpdateWhitelistSourceUseCase,
};
use ferrous_dns_domain::Config;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared state for the Pi-hole compatible API handlers.
///
/// Organised into domain sub-structs matching the Ferrous `AppState` pattern.
/// The Pi-hole API never accesses infrastructure directly — all reads
/// go through the same use cases as the Ferrous dashboard API.
#[derive(Clone)]
pub struct PiholeAppState {
    pub query: PiholeQueryState,
    pub blocking: PiholeBlockingState,
    pub lists: PiholeListsState,
    pub groups: PiholeGroupState,
    pub clients: PiholeClientState,
    pub system: PiholeSystemState,
    /// Optional API key — when `Some`, POST /api/auth validates against it.
    pub api_key: Option<Arc<str>>,
}

#[derive(Clone)]
pub struct PiholeQueryState {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_timeline: Arc<GetTimelineUseCase>,
    pub get_top_blocked_domains: Arc<GetTopBlockedDomainsUseCase>,
    pub get_top_allowed_domains: Arc<GetTopAllowedDomainsUseCase>,
    pub get_top_clients: Arc<GetTopClientsUseCase>,
    pub get_recent_queries: Arc<GetRecentQueriesUseCase>,
    pub upstream_health: Arc<dyn UpstreamHealthPort>,
    pub get_block_filter_stats: Arc<GetBlockFilterStatsUseCase>,
    pub get_cache_stats: Arc<GetCacheStatsUseCase>,
}

#[derive(Clone)]
pub struct PiholeBlockingState {
    pub block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    pub get_managed_domains: Arc<GetManagedDomainsUseCase>,
    pub create_managed_domain: Arc<CreateManagedDomainUseCase>,
    pub update_managed_domain: Arc<UpdateManagedDomainUseCase>,
    pub delete_managed_domain: Arc<DeleteManagedDomainUseCase>,
    pub get_regex_filters: Arc<GetRegexFiltersUseCase>,
    pub create_regex_filter: Arc<CreateRegexFilterUseCase>,
    pub update_regex_filter: Arc<UpdateRegexFilterUseCase>,
    pub delete_regex_filter: Arc<DeleteRegexFilterUseCase>,
    /// Blocking pause timer handle — only one active at a time per instance.
    pub blocking_timer: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Clone)]
pub struct PiholeListsState {
    pub get_blocklist_sources: Arc<GetBlocklistSourcesUseCase>,
    pub create_blocklist_source: Arc<CreateBlocklistSourceUseCase>,
    pub update_blocklist_source: Arc<UpdateBlocklistSourceUseCase>,
    pub delete_blocklist_source: Arc<DeleteBlocklistSourceUseCase>,
    pub get_whitelist_sources: Arc<GetWhitelistSourcesUseCase>,
    pub create_whitelist_source: Arc<CreateWhitelistSourceUseCase>,
    pub update_whitelist_source: Arc<UpdateWhitelistSourceUseCase>,
    pub delete_whitelist_source: Arc<DeleteWhitelistSourceUseCase>,
}

#[derive(Clone)]
pub struct PiholeGroupState {
    pub get_groups: Arc<GetGroupsUseCase>,
    pub create_group: Arc<CreateGroupUseCase>,
    pub update_group: Arc<UpdateGroupUseCase>,
    pub delete_group: Arc<DeleteGroupUseCase>,
}

#[derive(Clone)]
pub struct PiholeClientState {
    pub get_clients: Arc<GetClientsUseCase>,
    pub create_manual_client: Arc<CreateManualClientUseCase>,
    pub update_client: Arc<UpdateClientUseCase>,
    pub delete_client: Arc<DeleteClientUseCase>,
    pub assign_client_group: Arc<AssignClientGroupUseCase>,
}

#[derive(Clone)]
pub struct PiholeSystemState {
    pub cleanup_query_logs: Arc<CleanupOldQueryLogsUseCase>,
    pub config: Arc<RwLock<Config>>,
    pub config_path: Option<Arc<str>>,
    pub process_start: std::time::Instant,
}
