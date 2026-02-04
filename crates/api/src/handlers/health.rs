use tracing::info;

pub async fn health_check() -> &'static str {
    info!("Health check requested");
    "OK"
}
