use ferrous_dns_domain::{SafeSearchConfig, SafeSearchEngine, YouTubeMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct SafeSearchConfigResponse {
    pub id: Option<i64>,
    pub group_id: i64,
    pub engine: String,
    pub enabled: bool,
    pub youtube_mode: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl SafeSearchConfigResponse {
    pub fn from_entity(c: SafeSearchConfig) -> Self {
        Self {
            id: c.id,
            group_id: c.group_id,
            engine: c.engine.to_str().to_string(),
            enabled: c.enabled,
            youtube_mode: c.youtube_mode.to_str().to_string(),
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToggleSafeSearchRequest {
    pub engine: String,
    pub enabled: bool,
    pub youtube_mode: Option<String>,
}

impl ToggleSafeSearchRequest {
    /// Parses the engine string. Returns `None` if unknown.
    pub fn parse_engine(&self) -> Option<SafeSearchEngine> {
        self.engine.parse().ok()
    }

    /// Parses the youtube_mode string, defaulting to `Strict`.
    pub fn parse_youtube_mode(&self) -> YouTubeMode {
        self.youtube_mode
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }
}
