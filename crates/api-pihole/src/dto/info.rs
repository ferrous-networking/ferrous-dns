use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/info/version response.
#[derive(Debug, Serialize, ToSchema)]
pub struct VersionResponse {
    pub version: String,
    pub branch: String,
    pub hash: String,
}

/// Pi-hole v6 GET /api/info/ftl response (FTL daemon info).
#[derive(Debug, Serialize, ToSchema)]
pub struct FtlInfoResponse {
    pub pid: u32,
    pub uptime: u64,
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    pub database: FtlDatabaseInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FtlDatabaseInfo {
    pub gravity: u64,
    pub queries: u64,
}

/// Pi-hole v6 GET /api/info/system response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemInfoResponse {
    pub load: [f64; 3],
    pub memory: MemoryInfo,
    pub disk: DiskInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    pub percent: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DiskInfo {
    pub total: u64,
    pub used: u64,
    pub percent: f64,
}

/// Pi-hole v6 GET /api/info/host response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostInfoResponse {
    pub hostname: String,
}

/// Pi-hole v6 GET /api/info/database response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DatabaseInfoResponse {
    pub queries: u64,
    pub filesize: u64,
}
