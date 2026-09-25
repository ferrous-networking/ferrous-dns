use axum::extract::State;
use axum::Json;

use crate::{dto::action::ActionResponse, errors::PiholeApiError, state::PiholeAppState};

/// Pi-hole v6 POST /api/action/gravity — trigger blocklist reload.
#[utoipa::path(
    post,
    path = "/action/gravity",
    tag = "pihole:action",
    responses(
        (status = 200, description = "Blocklist reload triggered", body = ActionResponse),
        (status = 500, description = "Reload failed")
    ),
    security(("session_id" = []))
)]
pub async fn gravity(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    state.blocking.block_filter_engine.refresh_lists().await?;
    Ok(Json(ActionResponse {
        status: "success",
        message: "Blocklist reload completed".to_string(),
    }))
}

/// Pi-hole v6 POST /api/action/restartdns — reload configuration.
///
/// Re-reads the config file like `POST /api/config/reload`: command-line
/// overrides re-applied, upstream pools hot-reloaded. No process restart.
#[utoipa::path(
    post,
    path = "/action/restartdns",
    tag = "pihole:action",
    responses(
        (status = 200, description = "Configuration reloaded", body = ActionResponse),
        (status = 500, description = "Reload failed")
    ),
    security(("session_id" = []))
)]
pub async fn restartdns(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    if let Some(reload) = state.system.reload_config.clone() {
        reload.execute().await?;
    }

    Ok(Json(ActionResponse {
        status: "success",
        message: "DNS configuration reloaded".to_string(),
    }))
}

/// Pi-hole v6 POST /api/action/flush/logs — cleanup old query logs.
#[utoipa::path(
    post,
    path = "/action/flush/logs",
    tag = "pihole:action",
    responses(
        (status = 200, description = "Query logs flushed", body = ActionResponse),
        (status = 500, description = "Flush failed")
    ),
    security(("session_id" = []))
)]
pub async fn flush_logs(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    let deleted = state.system.cleanup_query_logs.execute(0).await?;
    Ok(Json(ActionResponse {
        status: "success",
        message: format!("Flushed {deleted} query log entries"),
    }))
}
