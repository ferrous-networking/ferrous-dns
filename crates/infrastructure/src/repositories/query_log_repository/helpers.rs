use super::rollup::minute_bucket;
use chrono::Utc;
use ferrous_dns_domain::{
    BlockSource, ClientProtocol, DnssecStatus, QueryLog, QuerySource, RecordType,
};
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use std::net::IpAddr;
use std::sync::Arc;

/// First rollup bucket of a window ending now. Rollup-backed reads are
/// minute-aligned: they include the whole minute the window starts in.
/// Saturates at the epoch so an absurd window can't overflow the subtraction.
pub fn window_start_bucket(hours: f32) -> i64 {
    let window_secs = (hours * 3_600.0) as i64;
    minute_bucket(Utc::now().timestamp().saturating_sub(window_secs).max(0))
}

fn to_static_response_status(s: &str) -> Option<&'static str> {
    match s {
        "NOERROR" => Some("NOERROR"),
        "NXDOMAIN" => Some("NXDOMAIN"),
        "SERVFAIL" => Some("SERVFAIL"),
        "REFUSED" => Some("REFUSED"),
        "TIMEOUT" => Some("TIMEOUT"),
        "BLOCKED" => Some("BLOCKED"),
        "LOCAL_DNS" => Some("LOCAL_DNS"),
        "RATE_LIMITED" => Some("RATE_LIMITED"),
        "RATE_LIMITED_TC" => Some("RATE_LIMITED_TC"),
        "SAFE_SEARCH" => Some("SAFE_SEARCH"),
        _ => None,
    }
}

/// Parses the comma-separated `answers` column back into addresses. Unparseable
/// entries are skipped; an empty result is treated as "no answers logged".
fn parse_answers(raw: Option<String>) -> Option<Arc<Vec<IpAddr>>> {
    let addresses: Vec<IpAddr> = raw?
        .split(',')
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();
    (!addresses.is_empty()).then(|| Arc::new(addresses))
}

pub fn row_to_query_log(row: SqliteRow) -> Option<QueryLog> {
    let client_ip_str: String = row.get("client_ip");
    let record_type_str: String = row.get("record_type");
    let domain_str: String = row.get("domain");

    let dnssec_status: Option<DnssecStatus> = row
        .get::<Option<String>, _>("dnssec_status")
        .and_then(|s| s.parse().ok());
    let response_status: Option<&'static str> = row
        .get::<Option<String>, _>("response_status")
        .and_then(|s| to_static_response_status(&s));

    let query_source = row
        .get::<Option<String>, _>("query_source")
        .and_then(|s| s.parse().ok())
        .unwrap_or(QuerySource::Client);
    let protocol: Option<ClientProtocol> = row
        .get::<Option<String>, _>("protocol")
        .and_then(|s| s.parse().ok());
    let block_source: Option<BlockSource> = row
        .get::<Option<String>, _>("block_source")
        .and_then(|s| s.parse().ok());
    let coalesced = row
        .get::<Option<String>, _>("coalesced")
        .and_then(|s| s.parse().ok());

    Some(QueryLog {
        id: Some(row.get("id")),
        domain: Arc::from(domain_str.as_str()),
        record_type: record_type_str.parse::<RecordType>().ok()?,
        client_ip: client_ip_str.parse().ok()?,
        client_hostname: row
            .get::<Option<String>, _>("hostname")
            .map(|s| Arc::from(s.as_str())),
        blocked: row.get::<i64, _>("blocked") != 0,
        response_time_us: row
            .get::<Option<i64>, _>("response_time_ms")
            .map(|t| t as u64),
        cache_hit: row.get::<i64, _>("cache_hit") != 0,
        cache_refresh: row.get::<i64, _>("cache_refresh") != 0,
        dnssec_status,
        dns64_synthesized: row.get::<i64, _>("dns64_synthesized") != 0,
        answers: parse_answers(row.get("answers")),
        upstream_server: row
            .get::<Option<String>, _>("upstream_server")
            .map(|s| Arc::from(s.as_str())),
        upstream_pool: row
            .get::<Option<String>, _>("upstream_pool")
            .map(|s| Arc::from(s.as_str())),
        response_status,
        // `datetime()` yields NULL for an unparseable stored value.
        timestamp: row.get("created_at"),
        query_source,
        protocol,
        group_id: row.get("group_id"),
        block_source,
        coalesced,
    })
}
