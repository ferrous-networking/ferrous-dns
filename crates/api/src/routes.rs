use crate::handlers;
use crate::middleware::require_auth;
use crate::openapi::ApiDoc;
use crate::state::AppState;
use axum::{middleware, Router};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

/// Builds the API router and returns the matching OpenAPI document.
///
/// All handlers exposed here are annotated with `#[utoipa::path]` so the
/// `OpenApiRouter::routes(routes!(...))` macro registers both the axum
/// route and its OpenAPI path operation. Submodules that already return a
/// classic `axum::Router` are merged in via the `From<Router>` impl
/// (their routes still work but aren't reflected in the spec — each
/// submodule annotates handlers individually and exposes them via its
/// own `OpenApiRouter` builder).
pub fn create_api_router_with_openapi(state: AppState) -> (Router, utoipa::openapi::OpenApi) {
    let public_routes = OpenApiRouter::new()
        .routes(routes!(handlers::auth::get_auth_status_public))
        .routes(routes!(handlers::auth::setup_password_public))
        .routes(routes!(handlers::auth::login_public))
        .routes(routes!(handlers::auth::logout_public));

    let core_routes = OpenApiRouter::new()
        .routes(routes!(handlers::health::health_check))
        .routes(routes!(handlers::dashboard::get_dashboard))
        .routes(routes!(handlers::stats::get_stats))
        .routes(routes!(handlers::rate::get_query_rate))
        .routes(routes!(handlers::timeline::get_timeline))
        .routes(routes!(handlers::queries::get_queries))
        .routes(routes!(handlers::blocklist::get_blocklist))
        .routes(routes!(handlers::whitelist::get_whitelist))
        .routes(routes!(handlers::cache::get_cache_stats))
        .routes(routes!(handlers::cache::get_cache_metrics))
        .routes(routes!(
            handlers::config::get::get_config,
            handlers::config::update::update_config
        ))
        .routes(routes!(handlers::config::update::reload_config))
        .routes(routes!(handlers::hostname::get_hostname))
        .routes(routes!(
            handlers::clients::get_clients,
            handlers::manual_clients::create_manual_client
        ))
        .routes(routes!(handlers::clients::get_client_stats))
        .routes(routes!(
            handlers::manual_clients::update_manual_client,
            handlers::manual_clients::delete_manual_client
        ))
        .routes(routes!(handlers::client_groups::assign_client_to_group))
        .routes(routes!(
            handlers::config::get::get_settings,
            handlers::config::update::update_settings
        ))
        .routes(routes!(handlers::upstream::get_upstream_health))
        .routes(routes!(handlers::upstream::get_upstream_health_detail))
        .routes(routes!(handlers::system_info::get_system_info))
        .routes(routes!(handlers::tls::get_tls_status))
        .routes(routes!(handlers::tls::upload_tls_certs))
        .routes(routes!(handlers::tls::generate_self_signed));

    let protected_router = core_routes
        .merge(handlers::groups::routes())
        .merge(handlers::client_subnets::routes())
        .merge(handlers::blocklist_sources::routes())
        .merge(handlers::whitelist_sources::routes())
        .merge(handlers::managed_domains::routes())
        .merge(handlers::regex_filters::routes())
        .merge(handlers::blocked_services::routes())
        .merge(handlers::custom_services::routes())
        .merge(handlers::local_records::routes())
        .merge(handlers::block_filter::routes())
        .merge(handlers::safe_search::routes())
        .merge(handlers::schedule_profiles::routes())
        .merge(handlers::auth::protected_routes())
        .merge(handlers::users::routes())
        .merge(handlers::api_tokens::routes())
        .merge(handlers::backup::routes())
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let (router, openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(public_routes)
        .merge(protected_router)
        .with_state(state)
        .split_for_parts();

    (router, openapi)
}

/// Backwards-compatible router builder that drops the OpenAPI document.
pub fn create_api_routes(state: AppState) -> Router {
    create_api_router_with_openapi(state).0
}
