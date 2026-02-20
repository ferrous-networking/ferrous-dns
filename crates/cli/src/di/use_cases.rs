use super::Repositories;
use ferrous_dns_application::services::SubnetMatcherService;
use ferrous_dns_application::use_cases::{
    AssignClientGroupUseCase, CleanupOldClientsUseCase, CleanupOldQueryLogsUseCase,
    CreateBlocklistSourceUseCase, CreateClientSubnetUseCase, CreateGroupUseCase,
    CreateManagedDomainUseCase, CreateManualClientUseCase, CreateRegexFilterUseCase,
    CreateWhitelistSourceUseCase, DeleteBlocklistSourceUseCase, DeleteClientSubnetUseCase,
    DeleteClientUseCase, DeleteGroupUseCase, DeleteManagedDomainUseCase, DeleteRegexFilterUseCase,
    DeleteWhitelistSourceUseCase, GetBlockFilterStatsUseCase, GetBlocklistSourcesUseCase,
    GetBlocklistUseCase, GetCacheStatsUseCase, GetClientSubnetsUseCase, GetClientsUseCase,
    GetGroupsUseCase, GetManagedDomainsUseCase, GetQueryRateUseCase, GetQueryStatsUseCase,
    GetRecentQueriesUseCase, GetRegexFiltersUseCase, GetTimelineUseCase,
    GetWhitelistSourcesUseCase, GetWhitelistUseCase, SyncArpCacheUseCase, SyncHostnamesUseCase,
    UpdateBlocklistSourceUseCase, UpdateGroupUseCase, UpdateManagedDomainUseCase,
    UpdateRegexFilterUseCase, UpdateWhitelistSourceUseCase,
};
use ferrous_dns_infrastructure::dns::PoolManager;
use ferrous_dns_infrastructure::system::{LinuxArpReader, PtrHostnameResolver};
use std::sync::Arc;

pub struct UseCases {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_timeline: Arc<GetTimelineUseCase>,
    pub get_query_rate: Arc<GetQueryRateUseCase>,
    pub get_blocklist: Arc<GetBlocklistUseCase>,
    pub get_block_filter_stats: Arc<GetBlockFilterStatsUseCase>,
    pub get_cache_stats: Arc<GetCacheStatsUseCase>,
    pub get_clients: Arc<GetClientsUseCase>,
    pub sync_arp: Arc<SyncArpCacheUseCase>,
    pub sync_hostnames: Arc<SyncHostnamesUseCase>,
    pub cleanup_clients: Arc<CleanupOldClientsUseCase>,
    pub cleanup_query_logs: Arc<CleanupOldQueryLogsUseCase>,
    pub get_groups: Arc<GetGroupsUseCase>,
    pub create_group: Arc<CreateGroupUseCase>,
    pub update_group: Arc<UpdateGroupUseCase>,
    pub delete_group: Arc<DeleteGroupUseCase>,
    pub assign_client_group: Arc<AssignClientGroupUseCase>,
    pub get_client_subnets: Arc<GetClientSubnetsUseCase>,
    pub create_client_subnet: Arc<CreateClientSubnetUseCase>,
    pub delete_client_subnet: Arc<DeleteClientSubnetUseCase>,
    pub create_manual_client: Arc<CreateManualClientUseCase>,
    pub delete_client: Arc<DeleteClientUseCase>,
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
    pub subnet_matcher: Arc<SubnetMatcherService>,
}

impl UseCases {
    pub fn new(repos: &Repositories, pool_manager: Arc<PoolManager>) -> Self {
        let arp_reader = Arc::new(LinuxArpReader::new());
        let hostname_resolver = Arc::new(PtrHostnameResolver::new(pool_manager, 5));

        let subnet_matcher = Arc::new(SubnetMatcherService::new(repos.client_subnet.clone()));

        Self {
            get_stats: Arc::new(GetQueryStatsUseCase::new(repos.query_log.clone())),
            get_queries: Arc::new(GetRecentQueriesUseCase::new(repos.query_log.clone())),
            get_timeline: Arc::new(GetTimelineUseCase::new(repos.query_log.clone())),
            get_query_rate: Arc::new(GetQueryRateUseCase::new(repos.query_log.clone())),
            get_blocklist: Arc::new(GetBlocklistUseCase::new(repos.blocklist.clone())),
            get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(
                repos.block_filter_engine.clone(),
            )),
            get_cache_stats: Arc::new(GetCacheStatsUseCase::new(repos.query_log.clone())),
            get_clients: Arc::new(GetClientsUseCase::new(repos.client.clone())),
            sync_arp: Arc::new(SyncArpCacheUseCase::new(arp_reader, repos.client.clone())),
            sync_hostnames: Arc::new(SyncHostnamesUseCase::new(
                repos.client.clone(),
                hostname_resolver,
            )),
            cleanup_clients: Arc::new(CleanupOldClientsUseCase::new(repos.client.clone())),
            cleanup_query_logs: Arc::new(CleanupOldQueryLogsUseCase::new(repos.query_log.clone())),
            get_groups: Arc::new(GetGroupsUseCase::new(repos.group.clone())),
            create_group: Arc::new(CreateGroupUseCase::new(repos.group.clone())),
            update_group: Arc::new(UpdateGroupUseCase::new(repos.group.clone())),
            delete_group: Arc::new(DeleteGroupUseCase::new(repos.group.clone())),
            assign_client_group: Arc::new(AssignClientGroupUseCase::new(
                repos.client.clone(),
                repos.group.clone(),
            )),
            get_client_subnets: Arc::new(GetClientSubnetsUseCase::new(repos.client_subnet.clone())),
            create_client_subnet: Arc::new(CreateClientSubnetUseCase::new(
                repos.client_subnet.clone(),
                repos.group.clone(),
            )),
            delete_client_subnet: Arc::new(DeleteClientSubnetUseCase::new(
                repos.client_subnet.clone(),
            )),
            create_manual_client: Arc::new(CreateManualClientUseCase::new(
                repos.client.clone(),
                repos.group.clone(),
            )),
            delete_client: Arc::new(DeleteClientUseCase::new(repos.client.clone())),
            get_blocklist_sources: Arc::new(GetBlocklistSourcesUseCase::new(
                repos.blocklist_source.clone(),
            )),
            create_blocklist_source: Arc::new(CreateBlocklistSourceUseCase::new(
                repos.blocklist_source.clone(),
                repos.group.clone(),
            )),
            update_blocklist_source: Arc::new(UpdateBlocklistSourceUseCase::new(
                repos.blocklist_source.clone(),
                repos.group.clone(),
            )),
            delete_blocklist_source: Arc::new(DeleteBlocklistSourceUseCase::new(
                repos.blocklist_source.clone(),
            )),
            get_whitelist: Arc::new(GetWhitelistUseCase::new(repos.whitelist.clone())),
            get_whitelist_sources: Arc::new(GetWhitelistSourcesUseCase::new(
                repos.whitelist_source.clone(),
            )),
            create_whitelist_source: Arc::new(CreateWhitelistSourceUseCase::new(
                repos.whitelist_source.clone(),
                repos.group.clone(),
            )),
            update_whitelist_source: Arc::new(UpdateWhitelistSourceUseCase::new(
                repos.whitelist_source.clone(),
                repos.group.clone(),
            )),
            delete_whitelist_source: Arc::new(DeleteWhitelistSourceUseCase::new(
                repos.whitelist_source.clone(),
            )),
            get_managed_domains: Arc::new(GetManagedDomainsUseCase::new(
                repos.managed_domain.clone(),
            )),
            create_managed_domain: Arc::new(CreateManagedDomainUseCase::new(
                repos.managed_domain.clone(),
                repos.group.clone(),
                repos.block_filter_engine.clone(),
            )),
            update_managed_domain: Arc::new(UpdateManagedDomainUseCase::new(
                repos.managed_domain.clone(),
                repos.group.clone(),
                repos.block_filter_engine.clone(),
            )),
            delete_managed_domain: Arc::new(DeleteManagedDomainUseCase::new(
                repos.managed_domain.clone(),
                repos.block_filter_engine.clone(),
            )),
            get_regex_filters: Arc::new(GetRegexFiltersUseCase::new(repos.regex_filter.clone())),
            create_regex_filter: Arc::new(CreateRegexFilterUseCase::new(
                repos.regex_filter.clone(),
                repos.group.clone(),
                repos.block_filter_engine.clone(),
            )),
            update_regex_filter: Arc::new(UpdateRegexFilterUseCase::new(
                repos.regex_filter.clone(),
                repos.group.clone(),
                repos.block_filter_engine.clone(),
            )),
            delete_regex_filter: Arc::new(DeleteRegexFilterUseCase::new(
                repos.regex_filter.clone(),
                repos.block_filter_engine.clone(),
            )),
            subnet_matcher,
        }
    }
}
