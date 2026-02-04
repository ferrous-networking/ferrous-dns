use super::Repositories;
use ferrous_dns_application::use_cases::{
    GetBlocklistUseCase, GetCacheStatsUseCase, GetConfigUseCase, GetQueryStatsUseCase,
    GetRecentQueriesUseCase, ReloadConfigUseCase, UpdateConfigUseCase,
};
use ferrous_dns_domain::Config;
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
}

impl UseCases {
    pub fn new(repos: &Repositories, config: Arc<RwLock<Config>>) -> Self {
        Self {
            get_stats: Arc::new(GetQueryStatsUseCase::new(repos.query_log.clone())),
            get_queries: Arc::new(GetRecentQueriesUseCase::new(repos.query_log.clone())),
            get_blocklist: Arc::new(GetBlocklistUseCase::new(repos.blocklist.clone())),
            get_cache_stats: Arc::new(GetCacheStatsUseCase::new()),
            get_config: Arc::new(GetConfigUseCase::new(repos.config.clone())),
            update_config: Arc::new(UpdateConfigUseCase::new(repos.config.clone())),
            reload_config: Arc::new(ReloadConfigUseCase::new(config)),
        }
    }
}
