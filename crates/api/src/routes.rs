use crate::handlers;
use crate::state::AppState;
use axum::{
    routing::{delete, get, post, put},
    Router,
};

pub fn create_api_routes(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/stats", get(handlers::get_stats))
        .route("/stats/rate", get(handlers::get_query_rate))
        .route("/queries/timeline", get(handlers::get_timeline))
        .route("/queries", get(handlers::get_queries))
        .route("/blocklist", get(handlers::get_blocklist))
        .route("/cache/stats", get(handlers::get_cache_stats))
        .route("/cache/metrics", get(handlers::get_cache_metrics))
        .route("/config", get(handlers::get_config))
        .route("/config", post(handlers::update_config))
        .route("/config/reload", post(handlers::reload_config))
        .route("/hostname", get(handlers::get_hostname))
        
        .route("/clients", get(handlers::get_clients))
        .route("/clients", post(handlers::create_manual_client))
        .route("/clients/stats", get(handlers::get_client_stats))
        .route("/clients/{id}", delete(handlers::delete_manual_client))
        .route("/clients/{id}/group", put(handlers::assign_client_to_group))
        
        .merge(handlers::groups::routes())
        
        .merge(handlers::client_subnets::routes())
        
        .merge(handlers::blocklist_sources::routes())
        
        .route("/settings", get(handlers::get_settings))
        .route("/settings", post(handlers::update_settings))
        
        .merge(handlers::local_records::routes())
        .with_state(state)
}
