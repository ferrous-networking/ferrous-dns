use ferrous_dns_application::use_cases::{
    GetBlocklistUseCase, GetQueryStatsUseCase, GetRecentQueriesUseCase,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_blocklist: Arc<GetBlocklistUseCase>,
}
