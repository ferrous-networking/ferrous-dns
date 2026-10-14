use axum::{middleware, Router};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::{
    handlers, middleware::require_pihole_auth, openapi::PiholeApiDoc, state::PiholeAppState,
};

/// Builds the Axum router for all Pi-hole v6 compatible endpoints together
/// with its OpenAPI document.
///
/// Mount the router at `/api` when `pihole_compat = true` so third-party
/// Pi-hole dashboards, plugins, and automations work without modification;
/// expose the spec under the same `nest` prefix (e.g. `/openapi.json` + `/docs`).
///
/// As on Pi-hole, only `/auth` and `/info/login` are public; every other
/// route sits behind [`require_pihole_auth`].
pub fn create_pihole_router_with_openapi(
    state: PiholeAppState,
) -> (Router, utoipa::openapi::OpenApi) {
    use utoipa::OpenApi;

    let public_routes = OpenApiRouter::new()
        .routes(routes!(
            handlers::auth::get_session,
            handlers::auth::login,
            handlers::auth::logout
        ))
        .routes(routes!(handlers::info::get_login_info));

    let protected_routes = OpenApiRouter::new()
        .routes(routes!(handlers::stats::get_summary))
        .routes(routes!(handlers::stats::get_history))
        .routes(routes!(handlers::stats::get_top_blocked))
        .routes(routes!(handlers::stats::get_top_clients))
        .routes(routes!(handlers::stats::get_query_types))
        .routes(routes!(handlers::stats::get_top_domains))
        .routes(routes!(handlers::stats::get_upstreams))
        .routes(routes!(handlers::stats::get_recent_blocked))
        // Aliases stay outside the spec to avoid duplicate operation ids.
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
        .route("/history", axum::routing::get(handlers::stats::get_history))
        .routes(routes!(handlers::history::get_history_clients))
        .routes(routes!(handlers::queries::get_queries))
        .routes(routes!(handlers::queries::get_suggestions))
        .routes(routes!(handlers::search::search_domain))
        .routes(routes!(
            handlers::dns::get_blocking,
            handlers::dns::set_blocking
        ))
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
        .routes(routes!(
            handlers::lists::list_all,
            handlers::lists::create_list
        ))
        .routes(routes!(
            handlers::lists::get_list,
            handlers::lists::update_list,
            handlers::lists::delete_list
        ))
        .routes(routes!(handlers::lists::batch_delete))
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
        .routes(routes!(handlers::info::get_version))
        .routes(routes!(handlers::info::get_ftl_info))
        .routes(routes!(handlers::info::get_system_info))
        .routes(routes!(handlers::info::get_host_info))
        .routes(routes!(handlers::info::get_database_info))
        .routes(routes!(handlers::action::gravity))
        .routes(routes!(handlers::action::restartdns))
        .routes(routes!(handlers::action::flush_logs))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_pihole_auth,
        ));

    OpenApiRouter::with_openapi(PiholeApiDoc::openapi())
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .split_for_parts()
}
