use tracing::info;

#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    responses(
        (status = 200, description = "Server is healthy", body = String),
    ),
    security(),
)]
pub async fn health_check() -> &'static str {
    info!("Health check requested");
    "OK"
}
