use ferrous_dns_application::services::SubnetMatcherService;
use ferrous_dns_application::use_cases::{
    AssignClientGroupUseCase, CreateClientSubnetUseCase, CreateGroupUseCase,
    CreateManualClientUseCase, DeleteClientSubnetUseCase, DeleteClientUseCase, DeleteGroupUseCase,
    GetBlocklistUseCase, GetClientSubnetsUseCase, GetClientsUseCase, GetGroupsUseCase,
    GetQueryStatsUseCase, GetRecentQueriesUseCase, UpdateGroupUseCase,
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{cache::DnsCache, HickoryDnsResolver};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_blocklist: Arc<GetBlocklistUseCase>,
    pub get_clients: Arc<GetClientsUseCase>,
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
    pub config: Arc<RwLock<Config>>,
    pub cache: Arc<DnsCache>,
    pub dns_resolver: Arc<HickoryDnsResolver>,
}
