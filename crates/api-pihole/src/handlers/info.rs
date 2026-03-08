use axum::extract::State;
use axum::Json;

use crate::{
    dto::info::{
        DatabaseInfoResponse, DiskInfo, FtlDatabaseInfo, FtlInfoResponse, HostInfoResponse,
        MemoryInfo, SystemInfoResponse, VersionResponse,
    },
    errors::PiholeApiError,
    state::PiholeAppState,
};

use super::stats::STATS_PERIOD_HOURS;

/// Pi-hole v6 GET /api/info/version
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        branch: "main".to_string(),
        hash: option_env!("GIT_HASH").unwrap_or("unknown").to_string(),
    })
}

/// Pi-hole v6 GET /api/info/ftl
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
pub async fn get_host_info() -> Json<HostInfoResponse> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());
    Json(HostInfoResponse { hostname })
}

/// Pi-hole v6 GET /api/info/database
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
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() >= 3 {
                Some([
                    parts[0].parse().unwrap_or(0.0),
                    parts[1].parse().unwrap_or(0.0),
                    parts[2].parse().unwrap_or(0.0),
                ])
            } else {
                None
            }
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

fn read_disk_usage() -> (u64, u64) {
    // Use statvfs for root filesystem.
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        let path = CString::new("/").unwrap();
        let mut stat = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: statvfs is a standard POSIX syscall, path is valid C string.
        let ret = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
        if ret == 0 {
            let stat = unsafe { stat.assume_init() };
            let total = stat.f_blocks * stat.f_frsize;
            let free = stat.f_bfree * stat.f_frsize;
            return (total, total.saturating_sub(free));
        }
    }
    (0, 0)
}
