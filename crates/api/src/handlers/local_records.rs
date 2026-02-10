use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use ferrous_dns_domain::LocalDnsRecord;
use tracing::{error, info, warn};

use crate::{dto::local_record::*, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/local-records", get(get_all_records))
        .route("/local-records", post(create_record))
        .route("/local-records/{id}", delete(delete_record))
}

/// GET /api/local-records - Get all local DNS records from config
async fn get_all_records(
    State(state): State<AppState>,
) -> Result<Json<Vec<LocalRecordDto>>, (StatusCode, String)> {
    let config = state.config.read().await;
    let local_domain = &config.dns.local_domain;

    // Convert config records to DTOs with index as ID
    let dtos: Vec<LocalRecordDto> = config
        .dns
        .local_records
        .iter()
        .enumerate()
        .map(|(idx, record)| LocalRecordDto::from_config(record, idx as i64, local_domain))
        .collect();

    Ok(Json(dtos))
}

/// POST /api/local-records - Create a new local DNS record
async fn create_record(
    State(state): State<AppState>,
    Json(req): Json<CreateLocalRecordRequest>,
) -> Result<Json<LocalRecordDto>, (StatusCode, String)> {
    // Validate IP address
    req.ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid IP address".to_string()))?;

    // Validate record type
    let record_type_upper = req.record_type.to_uppercase();
    if record_type_upper != "A" && record_type_upper != "AAAA" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid record type (must be A or AAAA)".to_string(),
        ));
    }

    // Create new record
    let new_record = LocalDnsRecord {
        hostname: req.hostname.clone(),
        domain: req.domain.clone(),
        ip: req.ip.clone(),
        record_type: record_type_upper,
        ttl: req.ttl,
    };

    // Add to config
    let mut config = state.config.write().await;
    config.dns.local_records.push(new_record.clone());

    let local_domain = config.dns.local_domain.clone();
    let new_index = config.dns.local_records.len() - 1;

    // Save config to file
    if let Err(e) = save_config_to_file(&config).await {
        // Rollback - remove from config
        config.dns.local_records.pop();
        error!(error = %e, "Failed to save config file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save configuration: {}", e),
        ));
    }

    // Drop write lock before cache operations
    drop(config);

    // Add to cache
    reload_cache_with_record(&state, &new_record, &local_domain).await;

    info!(
        hostname = %new_record.hostname,
        ip = %new_record.ip,
        record_type = %new_record.record_type,
        "Added local DNS record to config and cache"
    );

    // Convert to DTO
    let dto = LocalRecordDto::from_config(&new_record, new_index as i64, &local_domain);

    Ok(Json(dto))
}

/// DELETE /api/local-records/:id - Delete a local DNS record
async fn delete_record(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut config = state.config.write().await;

    // Validate index
    let idx = id as usize;
    if idx >= config.dns.local_records.len() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Record with id {} not found", id),
        ));
    }

    // Remove from config
    let removed_record = config.dns.local_records.remove(idx);
    let local_domain = config.dns.local_domain.clone();

    // Save config to file
    if let Err(e) = save_config_to_file(&config).await {
        // Rollback - re-add to config at same position
        config.dns.local_records.insert(idx, removed_record.clone());
        error!(error = %e, "Failed to save config file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save configuration: {}", e),
        ));
    }

    // Drop write lock before cache operations
    drop(config);

    // Clear from cache
    clear_cache_record(&state, &removed_record, &local_domain).await;

    info!(
        hostname = %removed_record.hostname,
        ip = %removed_record.ip,
        record_type = %removed_record.record_type,
        "Removed local DNS record from config and cache"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Save configuration to TOML file
async fn save_config_to_file(
    config: &ferrous_dns_domain::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Serialize to TOML
    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {}", e))?;

    // Write to file
    tokio::fs::write("ferrous-dns.toml", toml_str)
        .await
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    Ok(())
}

/// Add a single record to permanent cache
async fn reload_cache_with_record(
    state: &AppState,
    record: &LocalDnsRecord,
    default_domain: &Option<String>,
) {
    // Build FQDN
    let fqdn = record.fqdn(default_domain);

    // Parse IP
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

    // Parse record type
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

    // Get cache from resolver
    if let Some(cache) = state.dns_resolver.cache() {
        use ferrous_dns_infrastructure::dns::cache::CachedData;
        use std::sync::Arc;

        let data = CachedData::IpAddresses(Arc::new(vec![ip]));

        let ttl = record.ttl.unwrap_or(300);

        cache.insert_permanent(&fqdn, &record_type, data, ttl);

        info!(
            fqdn = %fqdn,
            ip = %ip,
            record_type = %record_type,
            "Added local DNS record to permanent cache"
        );
    }
}

/// Remove a record from cache
async fn clear_cache_record(
    state: &AppState,
    record: &LocalDnsRecord,
    default_domain: &Option<String>,
) {
    // Build FQDN
    let fqdn = record.fqdn(default_domain);

    // Parse record type
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

    // Get cache from resolver
    if let Some(cache) = state.dns_resolver.cache() {
        cache.remove(&fqdn, &record_type);

        info!(
            fqdn = %fqdn,
            record_type = %record_type,
            "Removed local DNS record from cache"
        );
    }
}
