use axum::extract::State;
use axum::Json;

use crate::{
    dto::info::{
        DatabaseInfoResponse, DiskInfo, FtlDatabaseInfo, FtlInfoResponse, HostInfoResponse,
        LoginInfoResponse, MemoryInfo, SystemInfoResponse, VersionResponse,
    },
    errors::PiholeApiError,
    state::PiholeAppState,
};

use super::stats::STATS_PERIOD_HOURS;

/// Pi-hole v6 GET /api/info/login
///
/// Public, as in FTL: clients such as Homarr probe it to tell Pi-hole v6
/// from v5, which has no such route. Ferrous does not track a failed DNS
/// listener, so `dns` is always true.
#[utoipa::path(
    get,
    path = "/info/login",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Login page info", body = LoginInfoResponse)
    ),
    security()
)]
pub async fn get_login_info(State(state): State<PiholeAppState>) -> Json<LoginInfoResponse> {
    Json(LoginInfoResponse {
        dns: true,
        https_port: state.system.https_port,
    })
}

/// Pi-hole v6 GET /api/info/version
#[utoipa::path(
    get,
    path = "/info/version",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Version info", body = VersionResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        branch: "main".to_string(),
        hash: option_env!("GIT_HASH").unwrap_or("unknown").to_string(),
    })
}

/// Pi-hole v6 GET /api/info/ftl
#[utoipa::path(
    get,
    path = "/info/ftl",
    tag = "pihole:info",
    responses(
        (status = 200, description = "FTL daemon info", body = FtlInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_ftl_info(
    State(state): State<PiholeAppState>,
) -> Result<Json<FtlInfoResponse>, PiholeApiError> {
    let uptime = state.system.process_start.elapsed().as_secs();
    let gravity = state.blocking.block_filter_engine.compiled_domain_count() as u64;

    let stats = state.query.get_stats.execute(STATS_PERIOD_HOURS).await?;

    Ok(Json(FtlInfoResponse {
        pid: std::process::id(),
        uptime,
        mem_percent: 0.0,
        cpu_percent: 0.0,
        database: FtlDatabaseInfo {
            gravity,
            queries: stats.queries_total,
        },
    }))
}

/// Pi-hole v6 GET /api/info/system
#[utoipa::path(
    get,
    path = "/info/system",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Host system info (load, memory, disk)", body = SystemInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_system_info() -> Json<SystemInfoResponse> {
    let (load, mem, disk) = tokio::task::spawn_blocking(|| {
        let load = read_loadavg();
        let mem = read_meminfo();
        let disk = read_disk_usage();
        (load, mem, disk)
    })
    .await
    .unwrap_or(([0.0; 3], (0, 0), (0, 0)));

    let (mem_total, mem_used) = mem;
    let (disk_total, disk_used) = disk;

    let mem_percent = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64) * 100.0
    } else {
        0.0
    };
    let disk_percent = if disk_total > 0 {
        (disk_used as f64 / disk_total as f64) * 100.0
    } else {
        0.0
    };

    Json(SystemInfoResponse {
        load,
        memory: MemoryInfo {
            total: mem_total,
            used: mem_used,
            percent: mem_percent,
        },
        disk: DiskInfo {
            total: disk_total,
            used: disk_used,
            percent: disk_percent,
        },
    })
}

/// Pi-hole v6 GET /api/info/host
#[utoipa::path(
    get,
    path = "/info/host",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Host hostname", body = HostInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_host_info() -> Json<HostInfoResponse> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());
    Json(HostInfoResponse { hostname })
}

/// Pi-hole v6 GET /api/info/database
#[utoipa::path(
    get,
    path = "/info/database",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Query database info", body = DatabaseInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_database_info(
    State(state): State<PiholeAppState>,
) -> Result<Json<DatabaseInfoResponse>, PiholeApiError> {
    let stats = state.query.get_stats.execute(STATS_PERIOD_HOURS).await?;
    Ok(Json(DatabaseInfoResponse {
        queries: stats.queries_total,
        filesize: 0,
    }))
}

fn read_loadavg() -> [f64; 3] {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| {
            let mut loads = s.split_whitespace().map(|v| v.parse().unwrap_or(0.0));
            Some([loads.next()?, loads.next()?, loads.next()?])
        })
        .unwrap_or([0.0; 3])
}

fn read_meminfo() -> (u64, u64) {
    let content = match std::fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    let mut total = 0u64;
    let mut available = 0u64;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("MemTotal:") {
            total = parse_kb_value(val);
        } else if let Some(val) = line.strip_prefix("MemAvailable:") {
            available = parse_kb_value(val);
        }
    }
    (total * 1024, total.saturating_sub(available) * 1024)
}

fn parse_kb_value(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// `(total, used)` bytes of the root filesystem.
#[cfg(target_os = "linux")]
fn read_disk_usage() -> (u64, u64) {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the path is a NUL-terminated literal and `stat` is writable
    // storage for exactly one `statvfs`, which is all the call writes.
    if unsafe { libc::statvfs(c"/".as_ptr(), stat.as_mut_ptr()) } != 0 {
        return (0, 0);
    }
    // SAFETY: statvfs returned 0, so it initialised every field of `stat`.
    let stat = unsafe { stat.assume_init() };
    let total = stat.f_blocks.saturating_mul(stat.f_frsize);
    let free = stat.f_bfree.saturating_mul(stat.f_frsize);
    (total, total.saturating_sub(free))
}

#[cfg(not(target_os = "linux"))]
fn read_disk_usage() -> (u64, u64) {
    (0, 0)
}
