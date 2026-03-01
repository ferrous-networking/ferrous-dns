use ferrous_dns_application::ports::{ConfigFilePersistence, DnsCachePort, UpstreamHealthPort};
use ferrous_dns_application::services::SubnetMatcherService;
use ferrous_dns_application::use_cases::{
    AssignClientGroupUseCase, BlockServiceUseCase, CreateBlocklistSourceUseCase,
    CreateClientSubnetUseCase, CreateCustomServiceUseCase, CreateGroupUseCase,
    CreateLocalRecordUseCase, CreateManagedDomainUseCase, CreateManualClientUseCase,
    CreateRegexFilterUseCase, CreateWhitelistSourceUseCase, DeleteBlocklistSourceUseCase,
    DeleteClientSubnetUseCase, DeleteClientUseCase, DeleteCustomServiceUseCase, DeleteGroupUseCase,
    DeleteLocalRecordUseCase, DeleteManagedDomainUseCase, DeleteRegexFilterUseCase,
    DeleteWhitelistSourceUseCase, GetBlockFilterStatsUseCase, GetBlockedServicesUseCase,
    GetBlocklistSourcesUseCase, GetBlocklistUseCase, GetCacheStatsUseCase, GetClientSubnetsUseCase,
    GetClientsUseCase, GetCustomServicesUseCase, GetGroupsUseCase, GetManagedDomainsUseCase,
    GetQueryRateUseCase, GetQueryStatsUseCase, GetRecentQueriesUseCase, GetRegexFiltersUseCase,
    GetServiceCatalogUseCase, GetTimelineUseCase, GetTopBlockedDomainsUseCase,
    GetTopClientsUseCase, GetWhitelistSourcesUseCase, GetWhitelistUseCase, UnblockServiceUseCase,
    UpdateBlocklistSourceUseCase, UpdateClientUseCase, UpdateCustomServiceUseCase,
    UpdateGroupUseCase, UpdateLocalRecordUseCase, UpdateManagedDomainUseCase,
    UpdateRegexFilterUseCase, UpdateWhitelistSourceUseCase,
};
use ferrous_dns_domain::Config;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct QueryUseCases {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_timeline: Arc<GetTimelineUseCase>,
    pub get_query_rate: Arc<GetQueryRateUseCase>,
    pub get_cache_stats: Arc<GetCacheStatsUseCase>,
    pub get_top_blocked_domains: Arc<GetTopBlockedDomainsUseCase>,
    pub get_top_clients: Arc<GetTopClientsUseCase>,
}

#[derive(Clone)]
pub struct DnsUseCases {
    pub cache: Arc<dyn DnsCachePort>,
    pub create_local_record: Arc<CreateLocalRecordUseCase>,
    pub update_local_record: Arc<UpdateLocalRecordUseCase>,
    pub delete_local_record: Arc<DeleteLocalRecordUseCase>,
    pub upstream_health: Arc<dyn UpstreamHealthPort>,
}

#[derive(Clone)]
pub struct GroupUseCases {
    pub get_groups: Arc<GetGroupsUseCase>,
    pub create_group: Arc<CreateGroupUseCase>,
    pub update_group: Arc<UpdateGroupUseCase>,
    pub delete_group: Arc<DeleteGroupUseCase>,
    pub assign_client_group: Arc<AssignClientGroupUseCase>,
}

#[derive(Clone)]
pub struct ClientUseCases {
    pub get_clients: Arc<GetClientsUseCase>,
    pub create_manual_client: Arc<CreateManualClientUseCase>,
    pub update_client: Arc<UpdateClientUseCase>,
    pub delete_client: Arc<DeleteClientUseCase>,
    pub get_client_subnets: Arc<GetClientSubnetsUseCase>,
    pub create_client_subnet: Arc<CreateClientSubnetUseCase>,
    pub delete_client_subnet: Arc<DeleteClientSubnetUseCase>,
    pub subnet_matcher: Arc<SubnetMatcherService>,
}

#[derive(Clone)]
pub struct BlockingUseCases {
    pub get_blocklist: Arc<GetBlocklistUseCase>,
    pub get_blocklist_sources: Arc<GetBlocklistSourcesUseCase>,
    pub create_blocklist_source: Arc<CreateBlocklistSourceUseCase>,
    pub update_blocklist_source: Arc<UpdateBlocklistSourceUseCase>,
    pub delete_blocklist_source: Arc<DeleteBlocklistSourceUseCase>,
    pub get_whitelist: Arc<GetWhitelistUseCase>,
    pub get_whitelist_sources: Arc<GetWhitelistSourcesUseCase>,
    pub create_whitelist_source: Arc<CreateWhitelistSourceUseCase>,
    pub update_whitelist_source: Arc<UpdateWhitelistSourceUseCase>,
    pub delete_whitelist_source: Arc<DeleteWhitelistSourceUseCase>,
    pub get_managed_domains: Arc<GetManagedDomainsUseCase>,
    pub create_managed_domain: Arc<CreateManagedDomainUseCase>,
    pub update_managed_domain: Arc<UpdateManagedDomainUseCase>,
    pub delete_managed_domain: Arc<DeleteManagedDomainUseCase>,
    pub get_regex_filters: Arc<GetRegexFiltersUseCase>,
    pub create_regex_filter: Arc<CreateRegexFilterUseCase>,
    pub update_regex_filter: Arc<UpdateRegexFilterUseCase>,
    pub delete_regex_filter: Arc<DeleteRegexFilterUseCase>,
    pub get_block_filter_stats: Arc<GetBlockFilterStatsUseCase>,
}

#[derive(Clone)]
pub struct ServiceUseCases {
    pub get_service_catalog: Arc<GetServiceCatalogUseCase>,
    pub get_blocked_services: Arc<GetBlockedServicesUseCase>,
    pub block_service: Arc<BlockServiceUseCase>,
    pub unblock_service: Arc<UnblockServiceUseCase>,
    pub create_custom_service: Arc<CreateCustomServiceUseCase>,
    pub get_custom_services: Arc<GetCustomServicesUseCase>,
    pub update_custom_service: Arc<UpdateCustomServiceUseCase>,
    pub delete_custom_service: Arc<DeleteCustomServiceUseCase>,
}

#[derive(Clone)]
pub struct AppState {
    pub query: QueryUseCases,
    pub dns: DnsUseCases,
    pub groups: GroupUseCases,
    pub clients: ClientUseCases,
    pub blocking: BlockingUseCases,
    pub services: ServiceUseCases,
    pub config: Arc<RwLock<Config>>,
    pub config_file_persistence: Arc<dyn ConfigFilePersistence>,
    pub api_key: Option<Arc<str>>,
}
