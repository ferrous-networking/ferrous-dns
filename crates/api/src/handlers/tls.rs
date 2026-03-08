use crate::{
    dto::{GenerateQuery, TlsStatusResponse, TlsUploadResponse},
    errors::ApiError,
    state::AppState,
};
use axum::{
    extract::{Multipart, Query, State},
    Json,
};
use ferrous_dns_domain::DomainError;
use std::path::Path;
use tracing::info;

/// GET /tls/status — returns certificate status information.
pub async fn get_tls_status(State(state): State<AppState>) -> Json<TlsStatusResponse> {
    let config = state.config.read().await;
    let web_tls = &config.server.web_tls;

    let status = state
        .tls_cert
        .get_status(&web_tls.tls_cert_path, &web_tls.tls_key_path)
        .await;

    Json(TlsStatusResponse {
        enabled: web_tls.enabled,
        cert_exists: status.cert_exists,
        key_exists: status.key_exists,
        cert_subject: status.cert_subject,
        cert_not_after: status.cert_not_after,
        cert_valid: status.cert_valid,
    })
}

/// POST /tls/upload — receives multipart with `cert` and `key` PEM files.
pub async fn upload_tls_certs(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<TlsUploadResponse>, ApiError> {
    let config = state.config.read().await;
    let cert_path = config.server.web_tls.tls_cert_path.clone();
    let key_path = config.server.web_tls.tls_key_path.clone();
    drop(config);

    let mut cert_data: Option<Vec<u8>> = None;
    let mut key_data: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match field.bytes().await {
            Ok(bytes) => match name.as_str() {
                "cert" => cert_data = Some(bytes.to_vec()),
                "key" => key_data = Some(bytes.to_vec()),
                _ => {}
            },
            Err(e) => {
                return Err(ApiError(DomainError::InvalidInput(format!(
                    "Failed to read field '{}': {}",
                    name, e
                ))));
            }
        }
    }

    let cert_bytes = cert_data.ok_or_else(|| {
        ApiError(DomainError::InvalidInput(
            "Missing 'cert' field in upload".into(),
        ))
    })?;

    let key_bytes = key_data.ok_or_else(|| {
        ApiError(DomainError::InvalidInput(
            "Missing 'key' field in upload".into(),
        ))
    })?;

    state
        .tls_cert
        .save_certificates(&cert_bytes, &key_bytes, &cert_path, &key_path)
        .await?;

    info!("TLS certificate and key uploaded successfully");

    Ok(Json(TlsUploadResponse {
        success: true,
        message: "Certificate and key uploaded successfully".to_string(),
        restart_required: true,
    }))
}

/// POST /tls/generate — generates a self-signed certificate.
pub async fn generate_self_signed(
    State(state): State<AppState>,
    Query(query): Query<GenerateQuery>,
) -> Result<Json<TlsUploadResponse>, ApiError> {
    let config = state.config.read().await;
    let cert_path = config.server.web_tls.tls_cert_path.clone();
    let key_path = config.server.web_tls.tls_key_path.clone();
    drop(config);

    if !query.force && Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
        return Err(ApiError(DomainError::InvalidInput(
            "Certificate files already exist. Use ?force=true to overwrite.".into(),
        )));
    }

    state
        .tls_cert
        .generate_self_signed(&cert_path, &key_path)
        .await?;

    info!("Self-signed TLS certificate generated successfully");

    Ok(Json(TlsUploadResponse {
        success: true,
        message: "Self-signed certificate generated successfully".to_string(),
        restart_required: true,
    }))
}
