use chrono::Utc;
use ferrous_dns_application::ports::TimeGranularity;
use ferrous_dns_domain::{BlockSource, QueryLog, QuerySource, RecordType};
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

pub fn granularity_to_sql(g: TimeGranularity) -> &'static str {
    match g {
        TimeGranularity::Minute => "strftime('%Y-%m-%d %H:%M:00', created_at)",
        TimeGranularity::QuarterHour => {
            "strftime('%Y-%m-%d %H:', created_at) || \
            printf('%02d', (CAST(strftime('%M', created_at) AS INTEGER) / 15) * 15) || \
            ':00'"
        }
        TimeGranularity::Hour => "strftime('%Y-%m-%d %H:00:00', created_at)",
        TimeGranularity::Day => "strftime('%Y-%m-%d 00:00:00', created_at)",
    }
}

pub fn hours_ago_cutoff(hours: f32) -> String {
    let ms = (hours * 3_600_000.0) as i64;
    (Utc::now() - chrono::Duration::milliseconds(ms))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

pub fn seconds_ago_cutoff(seconds: i64) -> String {
    (Utc::now() - chrono::Duration::seconds(seconds))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

pub fn days_ago_cutoff(days: u32) -> String {
    (Utc::now() - chrono::Duration::days(days as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn to_static_dnssec(s: &str) -> Option<&'static str> {
    match s {
        "Secure" => Some("Secure"),
        "Insecure" => Some("Insecure"),
        "Bogus" => Some("Bogus"),
        "Indeterminate" => Some("Indeterminate"),
        "Unknown" => Some("Unknown"),
        _ => None,
    }
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
        _ => None,
    }
}

pub fn row_to_query_log(row: SqliteRow) -> Option<QueryLog> {
    let client_ip_str: String = row.get("client_ip");
    let record_type_str: String = row.get("record_type");
    let domain_str: String = row.get("domain");

    let dnssec_status: Option<&'static str> = row
        .get::<Option<String>, _>("dnssec_status")
        .and_then(|s| to_static_dnssec(&s));
    let response_status: Option<&'static str> = row
        .get::<Option<String>, _>("response_status")
        .and_then(|s| to_static_response_status(&s));

    let query_source_str: String = row
        .get::<Option<String>, _>("query_source")
        .unwrap_or_else(|| "client".to_string());
    let query_source = QuerySource::from_str(&query_source_str).unwrap_or(QuerySource::Client);

    let block_source: Option<BlockSource> =
        row.get::<Option<String>, _>("block_source")
            .and_then(|s| match s.as_str() {
                "blocklist" => Some(BlockSource::Blocklist),
                "managed_domain" => Some(BlockSource::ManagedDomain),
                "regex_filter" => Some(BlockSource::RegexFilter),
                "cname_cloaking" => Some(BlockSource::CnameCloaking),
                _ => None,
            });

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
        upstream_server: row
            .get::<Option<String>, _>("upstream_server")
            .map(|s| Arc::from(s.as_str())),
        upstream_pool: row
            .try_get::<Option<String>, _>("upstream_pool")
            .ok()
            .flatten()
            .map(|s| Arc::from(s.as_str())),
        response_status,
        timestamp: Some(row.get("created_at")),
        query_source,
        group_id: row.get("group_id"),
        block_source,
    })
}

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

pub fn get_uptime() -> u64 {
    let start = START_TIME.get_or_init(SystemTime::now);
    start.elapsed().unwrap_or_default().as_secs()
}
