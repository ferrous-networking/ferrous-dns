use axum::{
    routing::{get, post, put},
    Router,
};

use crate::{handlers, state::PiholeAppState};

/// Builds the Axum router for all Pi-hole v6 compatible endpoints.
///
/// Mount this at `/api` when `pihole_compat = true` so third-party Pi-hole
/// dashboards, plugins, and automations work without modification.
pub fn create_pihole_routes(state: PiholeAppState) -> Router {
    Router::new()
        // Auth
        .route(
            "/auth",
            get(handlers::auth::get_session)
                .post(handlers::auth::login)
                .delete(handlers::auth::logout),
        )
        // Stats — Phase 1
        .route("/stats/summary", get(handlers::stats::get_summary))
        .route("/stats/history", get(handlers::stats::get_history))
        .route("/stats/top_blocked", get(handlers::stats::get_top_blocked))
        .route("/stats/top_clients", get(handlers::stats::get_top_clients))
        .route("/stats/query_types", get(handlers::stats::get_query_types))
        .route("/stats/top_domains", get(handlers::stats::get_top_domains))
        .route("/stats/upstreams", get(handlers::stats::get_upstreams))
        .route(
            "/stats/recent_blocked",
            get(handlers::stats::get_recent_blocked),
        )
        // Stats — database aliases (same handlers, query params for period)
        .route("/stats/database/summary", get(handlers::stats::get_summary))
        .route(
            "/stats/database/top_domains",
            get(handlers::stats::get_top_domains),
        )
        .route(
            "/stats/database/top_clients",
            get(handlers::stats::get_top_clients),
        )
        .route(
            "/stats/database/upstreams",
            get(handlers::stats::get_upstreams),
        )
        .route(
            "/stats/database/query_types",
            get(handlers::stats::get_query_types),
        )
        // History — Phase 1
        .route("/history", get(handlers::stats::get_history))
        .route(
            "/history/clients",
            get(handlers::history::get_history_clients),
        )
        // Queries — Phase 2
        .route("/queries", get(handlers::queries::get_queries))
        .route(
            "/queries/suggestions",
            get(handlers::queries::get_suggestions),
        )
        // Search — Phase 2
        .route("/search/{domain}", get(handlers::search::search_domain))
        // DNS blocking — Phase 3
        .route(
            "/dns/blocking",
            get(handlers::dns::get_blocking).post(handlers::dns::set_blocking),
        )
        // Domains — Phase 4
        .route("/domains", get(handlers::domains::list_all))
        .route("/domains/{type}", get(handlers::domains::list_by_type))
        .route(
            "/domains/{type}/{kind}",
            get(handlers::domains::list_by_type_kind).post(handlers::domains::create_domain),
        )
        .route(
            "/domains/{type}/{kind}/{domain}",
            put(handlers::domains::update_domain).delete(handlers::domains::delete_domain),
        )
        .route(
            "/domains:batchDelete",
            post(handlers::domains::batch_delete),
        )
        // Lists — Phase 5
        .route(
            "/lists",
            get(handlers::lists::list_all).post(handlers::lists::create_list),
        )
        .route(
            "/lists/{id}",
            get(handlers::lists::get_by_id)
                .put(handlers::lists::update_list)
                .delete(handlers::lists::delete_list),
        )
        .route("/lists:batchDelete", post(handlers::lists::batch_delete))
        // Groups — Phase 6
        .route(
            "/groups",
            get(handlers::groups::list_all).post(handlers::groups::create_group),
        )
        .route(
            "/groups/{name}",
            get(handlers::groups::get_by_name)
                .put(handlers::groups::update_group)
                .delete(handlers::groups::delete_group),
        )
        .route("/groups:batchDelete", post(handlers::groups::batch_delete))
        // Clients — Phase 6
        .route(
            "/clients",
            get(handlers::clients::list_all).post(handlers::clients::create_client),
        )
        .route("/clients/_suggestions", get(handlers::clients::suggestions))
        .route(
            "/clients/{client}",
            put(handlers::clients::update_client).delete(handlers::clients::delete_client),
        )
        .route(
            "/clients:batchDelete",
            post(handlers::clients::batch_delete),
        )
        // Info — Phase 7
        .route("/info/version", get(handlers::info::get_version))
        .route("/info/ftl", get(handlers::info::get_ftl_info))
        .route("/info/system", get(handlers::info::get_system_info))
        .route("/info/host", get(handlers::info::get_host_info))
        .route("/info/database", get(handlers::info::get_database_info))
        // Actions — Phase 7
        .route("/action/gravity", post(handlers::action::gravity))
        .route("/action/restartdns", post(handlers::action::restartdns))
        .route("/action/flush/logs", post(handlers::action::flush_logs))
        .with_state(state)
}
