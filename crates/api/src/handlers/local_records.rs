use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use tracing::info;

use crate::{dto::local_record::*, errors::ApiError, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/local-records", get(get_all_records))
        .route("/local-records", post(create_record))
        .route(
            "/local-records/{id}",
            put(update_record).delete(delete_record),
        )
}

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
