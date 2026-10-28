use crate::{dto::HealthResponse, state::AppState};
use axum::{extract::State, http::StatusCode, Json};
use tracing::debug;

#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    responses(
        (status = 200, description = "The DNS listener is up", body = HealthResponse),
        (status = 503, description = "The DNS listener is down: its bind failed or every worker exited", body = HealthResponse),
    ),
    security(),
)]
pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    debug!("Health check requested");
    let (code, status) = if state.is_dns_listening() {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    };
    (
        code,
        Json(HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}
