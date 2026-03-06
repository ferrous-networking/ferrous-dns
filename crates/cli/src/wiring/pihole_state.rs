use ferrous_dns_api_pihole::PiholeAppState;
use std::sync::Arc;

use super::UseCases;

/// Constructs [`PiholeAppState`] by reusing the `Arc` use cases already
/// wired for the Ferrous dashboard API — zero duplication of business logic.
pub fn build_pihole_state(use_cases: &UseCases, api_key: Option<Arc<str>>) -> PiholeAppState {
    PiholeAppState {
        get_stats: use_cases.get_stats.clone(),
        get_timeline: use_cases.get_timeline.clone(),
        get_top_blocked_domains: use_cases.get_top_blocked_domains.clone(),
        get_top_clients: use_cases.get_top_clients.clone(),
        api_key,
    }
}
