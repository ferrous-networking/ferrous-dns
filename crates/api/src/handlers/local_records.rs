use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::info;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{dto::local_record::*, errors::ApiError, state::AppState};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_records, create_record))
        .routes(routes!(update_record, delete_record))
}

#[utoipa::path(
    get,
    path = "/local-records",
    tag = "local_records",
    responses(
        (status = 200, description = "All local DNS records", body = [LocalRecordDto]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_records(
    State(state): State<AppState>,
) -> Result<Json<Vec<LocalRecordDto>>, ApiError> {
    let config = state.config.read().await;
    let local_domain = &config.dns.local_domain;

    let dtos: Vec<LocalRecordDto> = config
        .dns
        .local_records
        .iter()
        .enumerate()
        .map(|(idx, record)| LocalRecordDto::from_config(record, idx as i64, local_domain))
        .collect();

    Ok(Json(dtos))
}

#[utoipa::path(
    post,
    path = "/local-records",
    tag = "local_records",
    request_body = CreateLocalRecordRequest,
    responses(
        (status = 201, description = "Local DNS record created", body = LocalRecordDto),
        (status = 400, description = "Invalid input"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_record(
    State(state): State<AppState>,
    Json(req): Json<CreateLocalRecordRequest>,
) -> Result<(StatusCode, Json<LocalRecordDto>), ApiError> {
    let (new_record, new_index) = state
        .dns
        .create_local_record
        .execute(req.hostname, req.domain, req.ip, req.record_type, req.ttl)
        .await?;

    let local_domain = state.config.read().await.dns.local_domain.clone();

    info!(
        hostname = %new_record.hostname,
        ip = %new_record.ip,
        record_type = %new_record.record_type,
        "Added local DNS record to config and cache"
    );

    let dto = LocalRecordDto::from_config(&new_record, new_index as i64, &local_domain);
    Ok((StatusCode::CREATED, Json(dto)))
}

#[utoipa::path(
    put,
    path = "/local-records/{id}",
    tag = "local_records",
    params(("id" = i64, Path, description = "Local record ID (index)")),
    request_body = UpdateLocalRecordRequest,
    responses(
        (status = 200, description = "Local DNS record updated", body = LocalRecordDto),
        (status = 404, description = "Record not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_record(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateLocalRecordRequest>,
) -> Result<Json<LocalRecordDto>, ApiError> {
    let (updated_record, _old_record) = state
        .dns
        .update_local_record
        .execute(
            id,
            req.hostname,
            req.domain,
            req.ip,
            req.record_type,
            req.ttl,
        )
        .await?;

    let local_domain = state.config.read().await.dns.local_domain.clone();

    info!(
        hostname = %updated_record.hostname,
        ip = %updated_record.ip,
        record_type = %updated_record.record_type,
        "Updated local DNS record in config and cache"
    );

    let dto = LocalRecordDto::from_config(&updated_record, id, &local_domain);
    Ok(Json(dto))
}

#[utoipa::path(
    delete,
    path = "/local-records/{id}",
    tag = "local_records",
    params(("id" = i64, Path, description = "Local record ID (index)")),
    responses(
        (status = 204, description = "Local DNS record deleted"),
        (status = 404, description = "Record not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_record(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let removed_record = state.dns.delete_local_record.execute(id).await?;

    info!(
        hostname = %removed_record.hostname,
        ip = %removed_record.ip,
        record_type = %removed_record.record_type,
        "Removed local DNS record from config and cache"
    );

    Ok(StatusCode::NO_CONTENT)
}
