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
        .route("/config", get(handlers::get_config))
        .route("/config", post(handlers::update_config))
        .with_state(state)
}
