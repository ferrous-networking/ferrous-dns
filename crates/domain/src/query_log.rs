use crate::dns_record::RecordType;
use std::net::IpAddr;
// ← Reutilizar RecordType

#[derive(Debug, Clone)]
pub struct QueryLog {
    pub id: Option<i64>,
    pub domain: String,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub blocked: bool,
    pub response_time_ms: Option<u64>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueryStats {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub unique_clients: u64,
    pub uptime_seconds: u64,
}
