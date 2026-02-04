use crate::dto::HostnameResponse;
use axum::Json;
use tracing::instrument;

#[instrument(skip_all, name = "api_get_hostname")]
pub async fn get_hostname() -> Json<HostnameResponse> {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "DNS Server".to_string());

    Json(HostnameResponse { hostname })
}
