use axum::{
    body::Bytes,
    extract::{Multipart, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ferrous_dns_application::use_cases::{BackupSnapshot, ImportSummary};
use tracing::{error, info, instrument};

use crate::{
    dto::backup::{ImportSummaryDto, ImportSummaryResponse},
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/config/export", get(export_config))
        .route("/config/import", post(import_config))
}

#[instrument(skip(state), name = "api_export_config")]
async fn export_config(State(state): State<AppState>) -> Result<Response, ApiError> {
    let bytes = state.backup.export.execute().await?;

    let filename = format!("ferrous-backup-{}.json", Utc::now().format("%Y-%m-%d"));
    let content_disposition = format!("attachment; filename=\"{}\"", filename);

    let response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE.as_str(), "application/json"),
            (
                header::CONTENT_DISPOSITION.as_str(),
                content_disposition.as_str(),
            ),
        ],
        bytes,
    )
        .into_response();

    info!("Configuration export served successfully");
    Ok(response)
}

#[instrument(skip(state, multipart), name = "api_import_config")]
async fn import_config(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<ImportSummaryResponse>, ApiError> {
    let file_bytes = read_backup_file_from_multipart(&mut multipart).await?;

    let snapshot = parse_backup_snapshot(&file_bytes)?;

    let summary = state.backup.import.execute(snapshot).await?;

    Ok(Json(into_response(summary)))
}

async fn read_backup_file_from_multipart(multipart: &mut Multipart) -> Result<Bytes, ApiError> {
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        ApiError(ferrous_dns_domain::DomainError::InvalidInput(format!(
            "Failed to read multipart field: {}",
            e
        )))
    })? {
        let Some(name) = field.name() else { continue };
        if name == "file" {
            let data = field.bytes().await.map_err(|e| {
                ApiError(ferrous_dns_domain::DomainError::InvalidInput(format!(
                    "Failed to read file bytes: {}",
                    e
                )))
            })?;
            return Ok(data);
        }
    }

    Err(ApiError(ferrous_dns_domain::DomainError::InvalidInput(
        "No 'file' field found in multipart form".to_string(),
    )))
}

fn parse_backup_snapshot(bytes: &[u8]) -> Result<BackupSnapshot, ApiError> {
    serde_json::from_slice(bytes).map_err(|e| {
        error!(error = %e, "Failed to parse backup file");
        ApiError(ferrous_dns_domain::DomainError::InvalidInput(format!(
            "Invalid backup file format: {}",
            e
        )))
    })
}

fn into_response(summary: ImportSummary) -> ImportSummaryResponse {
    let success = summary.errors.is_empty();
    ImportSummaryResponse {
        success,
        summary: ImportSummaryDto {
            config_updated: summary.config_updated,
            groups_imported: summary.groups_imported,
            groups_skipped: summary.groups_skipped,
            blocklist_sources_imported: summary.blocklist_sources_imported,
            blocklist_sources_skipped: summary.blocklist_sources_skipped,
            local_records_imported: summary.local_records_imported,
            local_records_skipped: summary.local_records_skipped,
        },
        errors: summary.errors,
    }
}
