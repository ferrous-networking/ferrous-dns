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
        .route("/config", get(handlers::get_config))
        .route("/config", post(handlers::update_config))
        .route("/hostname", get(handlers::get_hostname))
        .with_state(state)
}
