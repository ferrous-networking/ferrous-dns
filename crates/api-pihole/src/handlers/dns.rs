use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::{
    dto::dns::{BlockingStatusResponse, SetBlockingRequest},
    errors::PiholeApiError,
    state::PiholeAppState,
};

/// Pi-hole v6 GET /api/dns/blocking
pub async fn get_blocking(
    State(state): State<PiholeAppState>,
) -> Result<Json<BlockingStatusResponse>, PiholeApiError> {
    let blocking = state.blocking.block_filter_engine.is_blocking_enabled();
    Ok(Json(BlockingStatusResponse {
        blocking,
        timer: None,
    }))
}

/// Pi-hole v6 POST /api/dns/blocking
///
/// Sets blocking state. Optionally accepts a `timer` field (seconds) that
/// automatically re-enables blocking after the timer expires.
pub async fn set_blocking(
    State(state): State<PiholeAppState>,
    Json(body): Json<SetBlockingRequest>,
) -> Result<Json<BlockingStatusResponse>, PiholeApiError> {
    // Cancel any existing timer.
    let mut guard = state.blocking.blocking_timer.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
    }

    state
        .blocking
        .block_filter_engine
        .set_blocking_enabled(body.blocking);

    let timer = body.timer;

    // If disabling with a timer, schedule re-enable.
    if !body.blocking {
        if let Some(seconds) = timer.filter(|&s| s > 0) {
            let engine = Arc::clone(&state.blocking.block_filter_engine);
            let handle = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                engine.set_blocking_enabled(true);
            });
            *guard = Some(handle);
        }
    }

    Ok(Json(BlockingStatusResponse {
        blocking: body.blocking,
        timer,
    }))
}
