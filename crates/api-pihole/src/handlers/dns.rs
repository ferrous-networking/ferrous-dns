use axum::extract::State;
use axum::Json;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use crate::{
    dto::dns::{BlockingStatus, BlockingStatusResponse, SetBlockingRequest},
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
    let slot = state.blocking.blocking_timer.lock().await;
    Ok(Json(blocking_status(&state, slot.as_ref())))
}

fn blocking_status(
    state: &PiholeAppState,
    timer: Option<&BlockingTimer>,
) -> BlockingStatusResponse {
    BlockingStatusResponse {
        blocking: BlockingStatus::from_enabled(
            state.blocking.block_filter_engine.is_blocking_enabled(),
        ),
        timer: timer.and_then(remaining_secs),
    }
}

/// Seconds left on a pending timer, as FTL reports them (fractional).
fn remaining_secs(timer: &BlockingTimer) -> Option<f64> {
    let left = timer.deadline.saturating_duration_since(Instant::now());
    if timer.task.is_finished() || left.is_zero() {
        return None;
    }
    Some(left.as_secs_f64())
}

/// Pi-hole v6 POST /api/dns/blocking
///
/// Sets the blocking mode. With a `timer` (seconds) the mode flips back once
/// it elapses. Every request replaces any pending timer. As in FTL, the reply
/// is the resulting state.
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
    let deadline = match body.timer_secs() {
        Some(seconds) => Some(
            Duration::try_from_secs_f64(seconds)
                .ok()
                .and_then(|timer| Instant::now().checked_add(timer))
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

    Ok(Json(blocking_status(&state, slot.as_ref())))
}
