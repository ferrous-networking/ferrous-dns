use axum::extract::State;
use axum::Json;
use ferrous_dns_domain::Config;
use tracing::info;

use crate::{dto::action::ActionResponse, errors::PiholeApiError, state::PiholeAppState};

/// Pi-hole v6 POST /api/action/gravity — trigger blocklist reload.
pub async fn gravity(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    state.blocking.block_filter_engine.reload().await?;
    Ok(Json(ActionResponse {
        status: "success",
        message: "Blocklist reload completed".to_string(),
    }))
}

/// Pi-hole v6 POST /api/action/restartdns — reload configuration.
///
/// Re-reads the config file from disk and updates the shared config.
/// No process restart is needed — Ferrous DNS applies changes in-memory.
pub async fn restartdns(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    if let Some(ref path) = state.system.config_path {
        let new_config = Config::load(Some(path.as_ref()), Default::default())
            .map_err(|e| PiholeApiError(ferrous_dns_domain::DomainError::IoError(e.to_string())))?;
        let mut config_guard = state.system.config.write().await;
        *config_guard = new_config;
        info!("Configuration reloaded from {path}");
    }

    Ok(Json(ActionResponse {
        status: "success",
        message: "DNS configuration reloaded".to_string(),
    }))
}

/// Pi-hole v6 POST /api/action/flush/logs — cleanup old query logs.
pub async fn flush_logs(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    let deleted = state.system.cleanup_query_logs.execute(0).await?;
    Ok(Json(ActionResponse {
        status: "success",
        message: format!("Flushed {deleted} query log entries"),
    }))
}
