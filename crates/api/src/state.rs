use ferrous_dns_application::use_cases::{
    GetBlocklistUseCase, GetQueryStatsUseCase, GetRecentQueriesUseCase,
};
use ferrous_dns_domain::Config;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_blocklist: Arc<GetBlocklistUseCase>,
    pub config: Arc<RwLock<Config>>,
}
