use std::sync::Arc;

use axum::extract::OriginalUri;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use axum::{middleware, Extension, Router};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::{
    errors::pihole_error_response, handlers, middleware::require_pihole_auth,
    openapi::PiholeApiDoc, state::PiholeAppState,
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
        .routes(routes!(handlers::info::get_login_info))
        .routes(routes!(handlers::info::get_client_info));

    let protected_routes = OpenApiRouter::new()
        .routes(routes!(handlers::stats::get_summary))
        .routes(routes!(handlers::stats::get_history))
        .routes(routes!(handlers::stats::get_top_blocked))
        .routes(routes!(handlers::stats::get_top_clients))
        .routes(routes!(handlers::stats::get_query_types))
        .routes(routes!(handlers::stats::get_top_domains))
        .routes(routes!(handlers::stats::get_upstreams))
        .routes(routes!(handlers::stats::get_recent_blocked))
        .routes(routes!(handlers::stats::get_database_summary))
        .routes(routes!(handlers::stats::get_database_top_domains))
        .routes(routes!(handlers::stats::get_database_top_clients))
        .routes(routes!(handlers::stats::get_database_upstreams))
        .routes(routes!(handlers::stats::get_database_query_types))
        // The Ferrous alias stays outside the spec to avoid a duplicate
        // operation id.
        .route(
            "/stats/history",
            axum::routing::get(handlers::stats::get_history),
        )
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
            handlers::domains::get_domain,
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
        // FTL takes the rest of the URI as a list address, slashes and all.
        // The route stays out of the spec, which documents it as `{list}`.
        .route(
            "/lists/{list}/{*rest}",
            axum::routing::get(handlers::lists::get_list)
                .put(handlers::lists::update_list)
                .delete(handlers::lists::delete_list),
        )
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
            handlers::clients::get_client,
            handlers::clients::update_client,
            handlers::clients::delete_client
        ))
        // The same for a client subnet such as 10.0.0.0/24.
        .route(
            "/clients/{client}/{*rest}",
            axum::routing::get(handlers::clients::get_client)
                .put(handlers::clients::update_client)
                .delete(handlers::clients::delete_client),
        )
        .routes(routes!(handlers::clients::batch_delete))
        .routes(routes!(handlers::info::get_version))
        .routes(routes!(handlers::info::get_ftl_info))
        .routes(routes!(handlers::info::get_system_info))
        .routes(routes!(handlers::info::get_host_info))
        .routes(routes!(handlers::info::get_database_info))
        .routes(routes!(handlers::info::get_messages))
        .routes(routes!(handlers::info::get_sensors))
        .routes(routes!(handlers::info::get_metrics))
        .routes(routes!(handlers::info::get_messages_count))
        .routes(routes!(handlers::info::delete_messages))
        .routes(routes!(handlers::dhcp::get_leases))
        .routes(routes!(handlers::dhcp::delete_lease))
        .routes(routes!(handlers::action::gravity))
        .routes(routes!(handlers::action::restartdns))
        .routes(routes!(handlers::action::flush_logs))
        .routes(routes!(handlers::padd::get_padd))
        .routes(routes!(handlers::endpoints::get_endpoints))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_pihole_auth,
        ));

    let (router, openapi) = OpenApiRouter::with_openapi(PiholeApiDoc::openapi())
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .split_for_parts();

    // `/endpoints` lists the finished document, so it is built only now.
    let endpoints = Arc::new(handlers::endpoints::list_endpoints(&openapi));
    let router = router
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(Extension(endpoints));
    (router, openapi)
}

/// FTL's answer for a path it does not route (api.c), given before any
/// authentication check, with the full request path as the hint.
async fn not_found(OriginalUri(uri): OriginalUri) -> Response {
    pihole_error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Not found",
        Some(uri.path()),
    )
}

/// FTL's answer for a method a route does not take, with the method as the
/// hint; axum still adds the Allow header.
async fn method_not_allowed(method: Method) -> Response {
    pihole_error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method Not Allowed",
        Some(method.as_str()),
    )
}
