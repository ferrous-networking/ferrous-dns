use axum::extract::State;
use axum::Json;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use crate::{
    dto::dns::{BlockingStatusResponse, SetBlockingRequest},
    errors::PiholeApiError,
    extract::PiholeJson,
    state::{BlockingTimer, PiholeAppState},
};

/// Pi-hole v6 GET /api/dns/blocking
#[utoipa::path(
    get,
    path = "/dns/blocking",
    tag = "pihole:dns",
    responses(
        (status = 200, description = "Current blocking status and seconds until it flips back (null without a timer)", body = BlockingStatusResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_blocking(
    State(state): State<PiholeAppState>,
) -> Result<Json<BlockingStatusResponse>, PiholeApiError> {
    let timer = state
        .blocking
        .blocking_timer
        .lock()
        .await
        .as_ref()
        .and_then(remaining_secs);
    let blocking = state.blocking.block_filter_engine.is_blocking_enabled();
    Ok(Json(BlockingStatusResponse { blocking, timer }))
}

/// Whole seconds left, rounded up so a pending timer never reads as 0.
fn remaining_secs(timer: &BlockingTimer) -> Option<u64> {
    let left = timer.deadline.saturating_duration_since(Instant::now());
    if timer.task.is_finished() || left.is_zero() {
        return None;
    }
    Some(left.as_secs() + u64::from(left.subsec_nanos() > 0))
}

/// Pi-hole v6 POST /api/dns/blocking
///
/// Sets the blocking mode. With a `timer` (seconds) the mode flips back once
/// it elapses. Every request replaces any pending timer.
#[utoipa::path(
    post,
    path = "/dns/blocking",
    tag = "pihole:dns",
    request_body = SetBlockingRequest,
    responses(
        (status = 200, description = "Blocking state updated", body = BlockingStatusResponse),
        (status = 400, description = "Timer out of range")
    ),
    security(("session_id" = []))
)]
pub async fn set_blocking(
    State(state): State<PiholeAppState>,
    PiholeJson(body): PiholeJson<SetBlockingRequest>,
) -> Result<Json<BlockingStatusResponse>, PiholeApiError> {
    let deadline = match body.timer.filter(|&seconds| seconds > 0) {
        Some(seconds) => Some(
            Instant::now()
                .checked_add(Duration::from_secs(seconds))
                .ok_or_else(|| {
                    DomainError::InvalidInput(format!("timer {seconds} is too large"))
                })?,
        ),
        None => None,
    };

    let mut slot = state.blocking.blocking_timer.lock().await;
    if let Some(previous) = slot.take() {
        previous.task.abort();
    }

    let engine = &state.blocking.block_filter_engine;
    engine.set_blocking_enabled(body.blocking);

    if let Some(deadline) = deadline {
        let engine = Arc::clone(engine);
        let flipped = !body.blocking;
        let task = tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            engine.set_blocking_enabled(flipped);
        });
        *slot = Some(BlockingTimer { deadline, task });
    }

    Ok(Json(BlockingStatusResponse {
        blocking: body.blocking,
        timer: deadline.and(body.timer),
    }))
}
