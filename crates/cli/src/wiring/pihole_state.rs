use ferrous_dns_api_pihole::{
    state::{
        PiholeBlockingState, PiholeClientState, PiholeGroupState, PiholeListsState,
        PiholeQueryState, PiholeSystemState,
    },
    PiholeAppState,
};
use ferrous_dns_application::ports::{BlockFilterEnginePort, UpstreamHealthPort};
use ferrous_dns_domain::Config;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::UseCases;

/// Constructs [`PiholeAppState`] by reusing the `Arc` use cases already
/// wired for the Ferrous dashboard API — zero duplication of business logic.
pub fn build_pihole_state(
    use_cases: &UseCases,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    upstream_health: Arc<dyn UpstreamHealthPort>,
    config: Arc<RwLock<Config>>,
    api_key: Option<Arc<str>>,
    config_path: Option<Arc<str>>,
) -> PiholeAppState {
    PiholeAppState {
        query: PiholeQueryState {
            get_stats: use_cases.get_stats.clone(),
            get_timeline: use_cases.get_timeline.clone(),
            get_top_blocked_domains: use_cases.get_top_blocked_domains.clone(),
            get_top_allowed_domains: use_cases.get_top_allowed_domains.clone(),
            get_top_clients: use_cases.get_top_clients.clone(),
            get_recent_queries: use_cases.get_queries.clone(),
            upstream_health,
            get_block_filter_stats: use_cases.get_block_filter_stats.clone(),
            get_cache_stats: use_cases.get_cache_stats.clone(),
        },
        blocking: PiholeBlockingState {
            block_filter_engine,
            get_managed_domains: use_cases.get_managed_domains.clone(),
            create_managed_domain: use_cases.create_managed_domain.clone(),
            update_managed_domain: use_cases.update_managed_domain.clone(),
            delete_managed_domain: use_cases.delete_managed_domain.clone(),
            get_regex_filters: use_cases.get_regex_filters.clone(),
            create_regex_filter: use_cases.create_regex_filter.clone(),
            update_regex_filter: use_cases.update_regex_filter.clone(),
            delete_regex_filter: use_cases.delete_regex_filter.clone(),
            blocking_timer: Arc::new(Mutex::new(None)),
        },
        lists: PiholeListsState {
            get_blocklist_sources: use_cases.get_blocklist_sources.clone(),
            create_blocklist_source: use_cases.create_blocklist_source.clone(),
            update_blocklist_source: use_cases.update_blocklist_source.clone(),
            delete_blocklist_source: use_cases.delete_blocklist_source.clone(),
            get_whitelist_sources: use_cases.get_whitelist_sources.clone(),
            create_whitelist_source: use_cases.create_whitelist_source.clone(),
            update_whitelist_source: use_cases.update_whitelist_source.clone(),
            delete_whitelist_source: use_cases.delete_whitelist_source.clone(),
        },
        groups: PiholeGroupState {
            get_groups: use_cases.get_groups.clone(),
            create_group: use_cases.create_group.clone(),
            update_group: use_cases.update_group.clone(),
            delete_group: use_cases.delete_group.clone(),
        },
        clients: PiholeClientState {
            get_clients: use_cases.get_clients.clone(),
            create_manual_client: use_cases.create_manual_client.clone(),
            update_client: use_cases.update_client.clone(),
            delete_client: use_cases.delete_client.clone(),
            assign_client_group: use_cases.assign_client_group.clone(),
        },
        system: PiholeSystemState {
            cleanup_query_logs: use_cases.cleanup_query_logs.clone(),
            config,
            config_path,
            process_start: std::time::Instant::now(),
        },
        api_key,
    }
}
