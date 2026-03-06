use serde::Serialize;

/// System information snapshot: kernel version, CPU load averages, and memory usage.
#[derive(Debug, Serialize, Default)]
pub struct SystemInfoResponse {
    pub kernel: String,
    pub load_avg_1m: f32,
    pub load_avg_5m: f32,
    pub load_avg_15m: f32,
    pub mem_total_kb: u64,
    pub mem_used_kb: u64,
    pub mem_available_kb: u64,
    pub mem_used_percent: f32,
}
