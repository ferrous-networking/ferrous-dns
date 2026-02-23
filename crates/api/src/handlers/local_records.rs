use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use ferrous_dns_domain::LocalDnsRecord;
use tracing::{error, info, warn};

use crate::{dto::local_record::*, state::AppState};

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
) -> Result<Json<Vec<LocalRecordDto>>, (StatusCode, String)> {
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
) -> Result<Json<LocalRecordDto>, (StatusCode, String)> {
    req.ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid IP address".to_string()))?;

    let record_type_upper = req.record_type.to_uppercase();
    if record_type_upper != "A" && record_type_upper != "AAAA" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid record type (must be A or AAAA)".to_string(),
        ));
    }

    let new_record = LocalDnsRecord {
        hostname: req.hostname.clone(),
        domain: req.domain.clone(),
        ip: req.ip.clone(),
        record_type: record_type_upper,
        ttl: req.ttl,
    };

    let mut config = state.config.write().await;
    config.dns.local_records.push(new_record.clone());

    let local_domain = config.dns.local_domain.clone();
    let new_index = config.dns.local_records.len() - 1;

    if let Err(e) = save_config_to_file(&config).await {
        config.dns.local_records.pop();
        error!(error = %e, "Failed to save config file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save configuration: {}", e),
        ));
    }

    drop(config);

    reload_cache_with_record(&state, &new_record, &local_domain).await;

    info!(
        hostname = %new_record.hostname,
        ip = %new_record.ip,
        record_type = %new_record.record_type,
        "Added local DNS record to config and cache"
    );

    let dto = LocalRecordDto::from_config(&new_record, new_index as i64, &local_domain);

    Ok(Json(dto))
}

async fn update_record(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateLocalRecordRequest>,
) -> Result<Json<LocalRecordDto>, (StatusCode, String)> {
    req.ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid IP address".to_string()))?;

    let record_type_upper = req.record_type.to_uppercase();
    if record_type_upper != "A" && record_type_upper != "AAAA" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid record type (must be A or AAAA)".to_string(),
        ));
    }

    let updated_record = LocalDnsRecord {
        hostname: req.hostname.clone(),
        domain: req.domain.clone(),
        ip: req.ip.clone(),
        record_type: record_type_upper,
        ttl: req.ttl,
    };

    let mut config = state.config.write().await;

    let idx = id as usize;
    if idx >= config.dns.local_records.len() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Record with id {} not found", id),
        ));
    }

    let old_record = config.dns.local_records[idx].clone();
    let local_domain = config.dns.local_domain.clone();
    config.dns.local_records[idx] = updated_record.clone();

    if let Err(e) = save_config_to_file(&config).await {
        config.dns.local_records[idx] = old_record;
        error!(error = %e, "Failed to save config file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save configuration: {}", e),
        ));
    }

    drop(config);

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
) -> Result<StatusCode, (StatusCode, String)> {
    let mut config = state.config.write().await;

    let idx = id as usize;
    if idx >= config.dns.local_records.len() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Record with id {} not found", id),
        ));
    }

    let removed_record = config.dns.local_records.remove(idx);
    let local_domain = config.dns.local_domain.clone();

    if let Err(e) = save_config_to_file(&config).await {
        config.dns.local_records.insert(idx, removed_record.clone());
        error!(error = %e, "Failed to save config file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save configuration: {}", e),
        ));
    }

    drop(config);

    clear_cache_record(&state, &removed_record, &local_domain).await;

    info!(
        hostname = %removed_record.hostname,
        ip = %removed_record.ip,
        record_type = %removed_record.record_type,
        "Removed local DNS record from config and cache"
    );

    Ok(StatusCode::NO_CONTENT)
}

async fn save_config_to_file(
    config: &ferrous_dns_domain::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = ferrous_dns_domain::Config::get_config_path()
        .unwrap_or_else(|| "ferrous-dns.toml".to_string());
    config
        .save_local_records(&path)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
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

    use ferrous_dns_infrastructure::dns::{CachedAddresses, CachedData};
    use std::sync::Arc as StdArc;

    let data = CachedData::IpAddresses(CachedAddresses {
        addresses: StdArc::new(vec![ip]),
        cname_chain: vec![],
    });
    state.cache.insert_permanent(&fqdn, record_type, data, None);

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

    let removed = state.cache.remove(&fqdn, &record_type);

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
