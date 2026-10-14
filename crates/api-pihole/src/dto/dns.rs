use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Blocking mode as FTL reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BlockingStatus {
    Enabled,
    Disabled,
}

impl BlockingStatus {
    pub fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

/// Pi-hole v6 GET/POST /api/dns/blocking response.
#[derive(Debug, Serialize, ToSchema)]
pub struct BlockingStatusResponse {
    pub blocking: BlockingStatus,
    /// Seconds until the blocking mode flips back; `null` when no timer is pending.
    pub timer: Option<f64>,
}

/// Pi-hole v6 POST /api/dns/blocking request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetBlockingRequest {
    pub blocking: bool,
    /// Seconds after which `blocking` flips back. As in FTL, only a number
    /// above zero starts a timer; anything else (absent, `null`, `true`, 0)
    /// means none. Home Assistant sends `true` and floats such as `300.0`.
    #[serde(default)]
    #[schema(value_type = Option<f64>)]
    pub timer: Option<serde_json::Value>,
}

impl SetBlockingRequest {
    pub fn timer_secs(&self) -> Option<f64> {
        self.timer
            .as_ref()
            .and_then(serde_json::Value::as_f64)
            .filter(|seconds| *seconds > 0.0)
    }
}
