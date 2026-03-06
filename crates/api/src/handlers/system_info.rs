use crate::dto::SystemInfoResponse;
use axum::Json;
use tracing::instrument;

const PROC_VERSION: &str = "/proc/version";
const PROC_LOADAVG: &str = "/proc/loadavg";
const PROC_MEMINFO: &str = "/proc/meminfo";

#[instrument(skip_all, name = "api_get_system_info")]
pub async fn get_system_info() -> Json<SystemInfoResponse> {
    let (version_raw, loadavg_raw, meminfo_raw) = tokio::join!(
        tokio::fs::read_to_string(PROC_VERSION),
        tokio::fs::read_to_string(PROC_LOADAVG),
        tokio::fs::read_to_string(PROC_MEMINFO),
    );

    let kernel = parse_proc_version(version_raw.as_deref().unwrap_or(""));
    let (load_avg_1m, load_avg_5m, load_avg_15m) =
        parse_loadavg(loadavg_raw.as_deref().unwrap_or("")).unwrap_or((0.0, 0.0, 0.0));
    let (mem_total_kb, mem_available_kb) =
        parse_meminfo(meminfo_raw.as_deref().unwrap_or("")).unwrap_or((0, 0));

    let mem_used_kb = mem_total_kb.saturating_sub(mem_available_kb);
    let mem_used_percent = compute_mem_percent(mem_used_kb, mem_total_kb);

    Json(SystemInfoResponse {
        kernel,
        load_avg_1m,
        load_avg_5m,
        load_avg_15m,
        mem_total_kb,
        mem_used_kb,
        mem_available_kb,
        mem_used_percent,
    })
}

/// Extracts the kernel version string from `/proc/version` content.
/// Returns just the version token (e.g. "6.12.75-1-lts") to keep the response concise.
fn parse_proc_version(raw: &str) -> String {
    // Format: "Linux version 6.12.75-1-lts (build@host) ..."
    raw.split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string()
}

/// Parses `/proc/loadavg` and returns the 1-minute, 5-minute and 15-minute load averages.
/// Format: "0.42 0.38 0.31 2/512 1234"
fn parse_loadavg(raw: &str) -> Option<(f32, f32, f32)> {
    let mut parts = raw.split_whitespace();
    let a = parts.next()?.parse::<f32>().ok()?;
    let b = parts.next()?.parse::<f32>().ok()?;
    let c = parts.next()?.parse::<f32>().ok()?;
    Some((a, b, c))
}

/// Parses `/proc/meminfo` and returns (MemTotal_kB, MemAvailable_kB).
fn parse_meminfo(raw: &str) -> Option<(u64, u64)> {
    let mut total = None;
    let mut available = None;
    for line in raw.lines() {
        if line.starts_with("MemTotal:") {
            total = parse_meminfo_line(line);
        } else if line.starts_with("MemAvailable:") {
            available = parse_meminfo_line(line);
        }
        if total.is_some() && available.is_some() {
            break;
        }
    }
    Some((total?, available?))
}

/// Parses a single `/proc/meminfo` line like "MemTotal:        8192000 kB" → 8192000.
fn parse_meminfo_line(line: &str) -> Option<u64> {
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

/// Computes memory used percentage, clamped to [0.0, 100.0].
fn compute_mem_percent(used_kb: u64, total_kb: u64) -> f32 {
    if total_kb == 0 {
        return 0.0;
    }
    ((used_kb as f32 / total_kb as f32) * 100.0).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loadavg_returns_three_floats() {
        let (a, b, c) = parse_loadavg("0.42 0.38 0.31 2/512 1234\n").unwrap();
        assert!((a - 0.42).abs() < 0.001);
        assert!((b - 0.38).abs() < 0.001);
        assert!((c - 0.31).abs() < 0.001);
    }

    #[test]
    fn parse_loadavg_returns_none_on_empty() {
        assert!(parse_loadavg("").is_none());
    }

    #[test]
    fn parse_loadavg_returns_none_on_non_numeric() {
        assert!(parse_loadavg("abc def ghi\n").is_none());
    }

    #[test]
    fn parse_loadavg_returns_none_when_fewer_than_three_tokens() {
        assert!(parse_loadavg("0.42 0.38\n").is_none());
    }

    #[test]
    fn parse_meminfo_extracts_total_and_available() {
        let raw =
            "MemTotal:        8192000 kB\nMemFree:        2048000 kB\nMemAvailable:   4096000 kB\n";
        let (total, available) = parse_meminfo(raw).unwrap();
        assert_eq!(total, 8192000);
        assert_eq!(available, 4096000);
    }

    #[test]
    fn parse_meminfo_returns_none_when_fields_missing() {
        assert!(parse_meminfo("MemFree: 1000 kB\n").is_none());
    }

    #[test]
    fn parse_meminfo_line_returns_none_when_no_numeric_value() {
        assert!(parse_meminfo_line("MemTotal: invalid kB").is_none());
    }

    #[test]
    fn parse_proc_version_extracts_kernel_token() {
        let raw = "Linux version 6.12.75-1-lts (build@host) (gcc 14.2.0) #1 SMP\n";
        let kernel = parse_proc_version(raw);
        assert_eq!(kernel, "6.12.75-1-lts");
    }

    #[test]
    fn parse_proc_version_returns_unknown_on_empty() {
        assert_eq!(parse_proc_version(""), "unknown");
    }

    #[test]
    fn parse_proc_version_returns_unknown_on_non_standard_format() {
        assert_eq!(parse_proc_version("non-standard"), "unknown");
    }

    #[test]
    fn compute_mem_percent_normal_case() {
        let pct = compute_mem_percent(4096, 8192);
        assert!((pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn compute_mem_percent_clamped_when_used_exceeds_total() {
        let pct = compute_mem_percent(200, 100);
        assert_eq!(pct, 100.0);
    }

    #[test]
    fn compute_mem_percent_returns_zero_when_total_is_zero() {
        assert_eq!(compute_mem_percent(0, 0), 0.0);
    }
}
