use super::Repositories;
use ferrous_dns_application::services::SubnetMatcherService;
use ferrous_dns_application::use_cases::{
    AssignClientGroupUseCase, CleanupOldClientsUseCase, CreateClientSubnetUseCase,
    CreateGroupUseCase, CreateManualClientUseCase, DeleteClientSubnetUseCase, DeleteClientUseCase,
    DeleteGroupUseCase, GetBlocklistUseCase, GetCacheStatsUseCase, GetClientSubnetsUseCase,
    GetClientsUseCase, GetConfigUseCase, GetGroupsUseCase, GetQueryStatsUseCase,
    GetRecentQueriesUseCase, ReloadConfigUseCase, SyncArpCacheUseCase, SyncHostnamesUseCase,
    TrackClientUseCase, UpdateConfigUseCase, UpdateGroupUseCase,
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::PoolManager;
use ferrous_dns_infrastructure::system::{LinuxArpReader, PtrHostnameResolver};
use std::sync::Arc;
use tokio::sync::RwLock;

#[allow(dead_code)]
pub struct UseCases {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_blocklist: Arc<GetBlocklistUseCase>,
    pub get_cache_stats: Arc<GetCacheStatsUseCase>,
    pub get_config: Arc<GetConfigUseCase>,
    pub update_config: Arc<UpdateConfigUseCase>,
    pub reload_config: Arc<ReloadConfigUseCase>,
    pub get_clients: Arc<GetClientsUseCase>,
    pub track_client: Arc<TrackClientUseCase>,
    pub sync_arp: Arc<SyncArpCacheUseCase>,
    pub sync_hostnames: Arc<SyncHostnamesUseCase>,
    pub cleanup_clients: Arc<CleanupOldClientsUseCase>,
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
    pub subnet_matcher: Arc<SubnetMatcherService>,
}

impl UseCases {
    pub fn new(
        repos: &Repositories,
        config: Arc<RwLock<Config>>,
        pool_manager: Arc<PoolManager>,
    ) -> Self {
        let arp_reader = Arc::new(LinuxArpReader::new());
        let hostname_resolver = Arc::new(PtrHostnameResolver::new(pool_manager, 5));

        // Initialize SubnetMatcherService
        let subnet_matcher = Arc::new(SubnetMatcherService::new(repos.client_subnet.clone()));

        Self {
            get_stats: Arc::new(GetQueryStatsUseCase::new(repos.query_log.clone())),
            get_queries: Arc::new(GetRecentQueriesUseCase::new(repos.query_log.clone())),
            get_blocklist: Arc::new(GetBlocklistUseCase::new(repos.blocklist.clone())),
            get_cache_stats: Arc::new(GetCacheStatsUseCase::new()),
            get_config: Arc::new(GetConfigUseCase::new(repos.config.clone())),
            update_config: Arc::new(UpdateConfigUseCase::new(repos.config.clone())),
            reload_config: Arc::new(ReloadConfigUseCase::new(config)),
            get_clients: Arc::new(GetClientsUseCase::new(repos.client.clone())),
            track_client: Arc::new(TrackClientUseCase::new(repos.client.clone())),
            sync_arp: Arc::new(SyncArpCacheUseCase::new(arp_reader, repos.client.clone())),
            sync_hostnames: Arc::new(SyncHostnamesUseCase::new(
                repos.client.clone(),
                hostname_resolver,
            )),
            cleanup_clients: Arc::new(CleanupOldClientsUseCase::new(repos.client.clone())),
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
            subnet_matcher,
        }
    }
}
