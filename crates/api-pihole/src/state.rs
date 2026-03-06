use ferrous_dns_application::use_cases::{
    GetQueryStatsUseCase, GetTimelineUseCase, GetTopBlockedDomainsUseCase, GetTopClientsUseCase,
};
use std::sync::Arc;

/// Shared state for the Pi-hole compatible API handlers.
///
/// Each field is an `Arc<UseCase>` injected from the CLI wiring layer.
/// The Pi-hole API never accesses infrastructure directly — all reads
/// go through the same use cases as the Ferrous dashboard API.
#[derive(Clone)]
pub struct PiholeAppState {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_timeline: Arc<GetTimelineUseCase>,
    pub get_top_blocked_domains: Arc<GetTopBlockedDomainsUseCase>,
    pub get_top_clients: Arc<GetTopClientsUseCase>,
    /// Optional API key — when `Some`, POST /api/auth validates against it.
    pub api_key: Option<Arc<str>>,
}
