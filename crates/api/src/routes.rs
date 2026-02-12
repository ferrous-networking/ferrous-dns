use crate::handlers;
use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};

/// Creates all API routes with state
pub fn create_api_routes(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/stats", get(handlers::get_stats))
        .route("/queries", get(handlers::get_queries))
        .route("/blocklist", get(handlers::get_blocklist))
        .route("/cache/stats", get(handlers::get_cache_stats))
        .route("/cache/metrics", get(handlers::get_cache_metrics))
        .route("/config", get(handlers::get_config))
        .route("/config", post(handlers::update_config))
        .route("/config/reload", post(handlers::reload_config))
        .route("/hostname", get(handlers::get_hostname))
        // Clients endpoints
        .route("/clients", get(handlers::get_clients))
        .route("/clients/stats", get(handlers::get_client_stats))
        // DNS Settings (Pi-hole style)
        .route("/settings", get(handlers::get_settings))
        .route("/settings", post(handlers::update_settings))
        // Local DNS records routes (Fase 2)
        .merge(handlers::local_records::routes())
        .with_state(state)
}
