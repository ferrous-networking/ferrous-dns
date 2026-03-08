use crate::handlers;
use crate::middleware::require_auth;
use crate::state::AppState;
use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};

pub fn create_api_routes(state: AppState) -> Router {
    let public_auth_routes = Router::new()
        .route("/auth/status", get(handlers::auth::get_auth_status_public))
        .route("/auth/setup", post(handlers::auth::setup_password_public))
        .route("/auth/login", post(handlers::auth::login_public))
        .route("/auth/logout", post(handlers::auth::logout_public));

    let protected_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/dashboard", get(handlers::get_dashboard))
        .route("/stats", get(handlers::get_stats))
        .route("/stats/rate", get(handlers::get_query_rate))
        .route("/queries/timeline", get(handlers::get_timeline))
        .route("/queries", get(handlers::get_queries))
        .route("/blocklist", get(handlers::get_blocklist))
        .route("/whitelist", get(handlers::get_whitelist))
        .route("/cache/stats", get(handlers::get_cache_stats))
        .route("/cache/metrics", get(handlers::get_cache_metrics))
        .route("/config", get(handlers::get_config))
        .route("/config", post(handlers::update_config))
        .route("/config/reload", post(handlers::reload_config))
        .route("/hostname", get(handlers::get_hostname))
        .route("/clients", get(handlers::get_clients))
        .route("/clients", post(handlers::create_manual_client))
        .route("/clients/stats", get(handlers::get_client_stats))
        .route("/clients/{id}", patch(handlers::update_manual_client))
        .route("/clients/{id}", delete(handlers::delete_manual_client))
        .route("/clients/{id}/group", put(handlers::assign_client_to_group))
        .merge(handlers::groups::routes())
        .merge(handlers::client_subnets::routes())
        .merge(handlers::blocklist_sources::routes())
        .merge(handlers::whitelist_sources::routes())
        .merge(handlers::managed_domains::routes())
        .merge(handlers::regex_filters::routes())
        .merge(handlers::blocked_services::routes())
        .merge(handlers::custom_services::routes())
        .route("/settings", get(handlers::get_settings))
        .route("/settings", post(handlers::update_settings))
        .merge(handlers::local_records::routes())
        .merge(handlers::block_filter::routes())
        .merge(handlers::safe_search::routes())
        .merge(handlers::schedule_profiles::routes())
        .route(
            "/upstream/health",
            get(handlers::upstream::get_upstream_health),
        )
        .route(
            "/upstream/health/detail",
            get(handlers::upstream::get_upstream_health_detail),
        )
        .route("/system/info", get(handlers::get_system_info))
        .merge(handlers::auth::protected_routes())
        .merge(handlers::users::routes())
        .merge(handlers::api_tokens::routes())
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public_auth_routes)
        .merge(protected_routes)
        .with_state(state)
}
