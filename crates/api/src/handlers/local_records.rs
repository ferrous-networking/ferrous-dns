use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use ferrous_dns_domain::LocalDnsRecord;
use tracing::{info, warn};

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
    reload_cache_with_record(&state, &new_record, &local_domain).await;

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
    let (updated_record, old_record) = state
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
    clear_cache_record(&state, &old_record, &local_domain).await;
    reload_cache_with_record(&state, &updated_record, &local_domain).await;

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

    let local_domain = state.config.read().await.dns.local_domain.clone();
    clear_cache_record(&state, &removed_record, &local_domain).await;

    info!(
        hostname = %removed_record.hostname,
        ip = %removed_record.ip,
        record_type = %removed_record.record_type,
        "Removed local DNS record from config and cache"
    );

    Ok(StatusCode::NO_CONTENT)
}

async fn reload_cache_with_record(
    state: &AppState,
    record: &LocalDnsRecord,
    default_domain: &Option<String>,
) {
    let fqdn = record.fqdn(default_domain);

    let ip: std::net::IpAddr = match record.ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!(
                hostname = %record.hostname,
                ip = %record.ip,
                "Invalid IP address, cannot add to cache"
            );
            return;
        }
    };

    let record_type = match record.record_type.to_uppercase().as_str() {
        "A" => ferrous_dns_domain::RecordType::A,
        "AAAA" => ferrous_dns_domain::RecordType::AAAA,
        _ => {
            warn!(
                hostname = %record.hostname,
                record_type = %record.record_type,
                "Invalid record type, cannot add to cache"
            );
            return;
        }
    };

    state
        .dns
        .cache
        .insert_permanent_record(&fqdn, record_type, vec![ip]);

    info!(
        fqdn = %fqdn,
        ip = %ip,
        record_type = %record_type,
        "Added local DNS record to permanent cache"
    );
}

async fn clear_cache_record(
    state: &AppState,
    record: &LocalDnsRecord,
    default_domain: &Option<String>,
) {
    let fqdn = record.fqdn(default_domain);

    let record_type = match record.record_type.to_uppercase().as_str() {
        "A" => ferrous_dns_domain::RecordType::A,
        "AAAA" => ferrous_dns_domain::RecordType::AAAA,
        _ => {
            warn!(
                hostname = %record.hostname,
                record_type = %record.record_type,
                "Invalid record type, cannot remove from cache"
            );
            return;
        }
    };

    let removed = state.dns.cache.remove_record(&fqdn, &record_type);

    if removed {
        info!(
            fqdn = %fqdn,
            record_type = %record_type,
            "Removed local DNS record from cache"
        );
    } else {
        warn!(
            fqdn = %fqdn,
            record_type = %record_type,
            "Local DNS record not found in cache (may have already been removed)"
        );
    }
}
