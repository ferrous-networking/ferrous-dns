use axum::Router;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::{handlers, openapi::PiholeApiDoc, state::PiholeAppState};

/// Builds the Axum router for all Pi-hole v6 compatible endpoints.
///
/// Mount this at `/api` when `pihole_compat = true` so third-party Pi-hole
/// dashboards, plugins, and automations work without modification.
pub fn create_pihole_routes(state: PiholeAppState) -> Router {
    create_pihole_router_with_openapi(state).0
}

/// Builds the Axum router together with its OpenAPI document.
///
/// Returns a tuple `(Router, OpenApi)` so the caller can mount the router and
/// expose the spec under the same `nest` prefix (e.g. `/openapi.json` + `/docs`).
pub fn create_pihole_router_with_openapi(
    state: PiholeAppState,
) -> (Router, utoipa::openapi::OpenApi) {
    use utoipa::OpenApi;

    let (router, api) = OpenApiRouter::with_openapi(PiholeApiDoc::openapi())
        // Auth
        .routes(routes!(
            handlers::auth::get_session,
            handlers::auth::login,
            handlers::auth::logout
        ))
        // Stats — Phase 1
        .routes(routes!(handlers::stats::get_summary))
        .routes(routes!(handlers::stats::get_history))
        .routes(routes!(handlers::stats::get_top_blocked))
        .routes(routes!(handlers::stats::get_top_clients))
        .routes(routes!(handlers::stats::get_query_types))
        .routes(routes!(handlers::stats::get_top_domains))
        .routes(routes!(handlers::stats::get_upstreams))
        .routes(routes!(handlers::stats::get_recent_blocked))
        // Stats — database aliases (same handlers, different paths — keep but
        // outside the spec to avoid duplicate operation ids).
        .route(
            "/stats/database/summary",
            axum::routing::get(handlers::stats::get_summary),
        )
        .route(
            "/stats/database/top_domains",
            axum::routing::get(handlers::stats::get_top_domains),
        )
        .route(
            "/stats/database/top_clients",
            axum::routing::get(handlers::stats::get_top_clients),
        )
        .route(
            "/stats/database/upstreams",
            axum::routing::get(handlers::stats::get_upstreams),
        )
        .route(
            "/stats/database/query_types",
            axum::routing::get(handlers::stats::get_query_types),
        )
        // History — Phase 1
        .route("/history", axum::routing::get(handlers::stats::get_history))
        .routes(routes!(handlers::history::get_history_clients))
        // Queries — Phase 2
        .routes(routes!(handlers::queries::get_queries))
        .routes(routes!(handlers::queries::get_suggestions))
        // Search — Phase 2
        .routes(routes!(handlers::search::search_domain))
        // DNS blocking — Phase 3
        .routes(routes!(
            handlers::dns::get_blocking,
            handlers::dns::set_blocking
        ))
        // Domains — Phase 4
        .routes(routes!(handlers::domains::list_all))
        .routes(routes!(handlers::domains::list_by_type))
        .routes(routes!(
            handlers::domains::list_by_type_kind,
            handlers::domains::create_domain
        ))
        .routes(routes!(
            handlers::domains::update_domain,
            handlers::domains::delete_domain
        ))
        .routes(routes!(handlers::domains::batch_delete))
        // Lists — Phase 5
        .routes(routes!(
            handlers::lists::list_all,
            handlers::lists::create_list
        ))
        .routes(routes!(
            handlers::lists::get_by_id,
            handlers::lists::update_list,
            handlers::lists::delete_list
        ))
        .routes(routes!(handlers::lists::batch_delete))
        // Groups — Phase 6
        .routes(routes!(
            handlers::groups::list_all,
            handlers::groups::create_group
        ))
        .routes(routes!(
            handlers::groups::get_by_name,
            handlers::groups::update_group,
            handlers::groups::delete_group
        ))
        .routes(routes!(handlers::groups::batch_delete))
        // Clients — Phase 6
        .routes(routes!(
            handlers::clients::list_all,
            handlers::clients::create_client
        ))
        .routes(routes!(handlers::clients::suggestions))
        .routes(routes!(
            handlers::clients::update_client,
            handlers::clients::delete_client
        ))
        .routes(routes!(handlers::clients::batch_delete))
        // Info — Phase 7
        .routes(routes!(handlers::info::get_version))
        .routes(routes!(handlers::info::get_ftl_info))
        .routes(routes!(handlers::info::get_system_info))
        .routes(routes!(handlers::info::get_host_info))
        .routes(routes!(handlers::info::get_database_info))
        // Actions — Phase 7
        .routes(routes!(handlers::action::gravity))
        .routes(routes!(handlers::action::restartdns))
        .routes(routes!(handlers::action::flush_logs))
        .with_state(state)
        .split_for_parts();

    (router, api)
}
