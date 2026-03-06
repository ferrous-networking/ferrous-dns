use axum::{routing::get, Router};

use crate::{handlers, state::PiholeAppState};

/// Builds the Axum router for all Pi-hole v6 compatible endpoints.
///
/// Mount this at `/api` when `pihole_compat = true` so third-party Pi-hole
/// dashboards, plugins, and automations work without modification.
pub fn create_pihole_routes(state: PiholeAppState) -> Router {
    Router::new()
        .route(
            "/auth",
            get(handlers::auth::get_session)
                .post(handlers::auth::login)
                .delete(handlers::auth::logout),
        )
        .route("/stats/summary", get(handlers::stats::get_summary))
        .route("/stats/history", get(handlers::stats::get_history))
        .route("/stats/top_blocked", get(handlers::stats::get_top_blocked))
        .route("/stats/top_clients", get(handlers::stats::get_top_clients))
        .route("/stats/query_types", get(handlers::stats::get_query_types))
        .with_state(state)
}
