use serde::{Deserialize, Serialize};

/// Error returned when a string cannot be parsed as a known [`SafeSearchEngine`] variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSafeSearchEngine(pub String);

impl std::fmt::Display for UnknownSafeSearchEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown Safe Search engine: '{}'", self.0)
    }
}

/// Error returned when a string cannot be parsed as a known [`YouTubeMode`] variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownYouTubeMode(pub String);

impl std::fmt::Display for UnknownYouTubeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown YouTube mode: '{}'", self.0)
    }
}

/// Search engine covered by Safe Search enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafeSearchEngine {
    Google,
    Bing,
    YouTube,
    DuckDuckGo,
    Yandex,
    Brave,
    Ecosia,
}

impl SafeSearchEngine {
    /// Returns the canonical lowercase string representation used in the database and API.
    pub fn to_str(self) -> &'static str {
        match self {
            SafeSearchEngine::Google => "google",
            SafeSearchEngine::Bing => "bing",
            SafeSearchEngine::YouTube => "youtube",
            SafeSearchEngine::DuckDuckGo => "duckduckgo",
            SafeSearchEngine::Yandex => "yandex",
            SafeSearchEngine::Brave => "brave",
            SafeSearchEngine::Ecosia => "ecosia",
        }
    }

    /// Returns a slice of all supported engines in a stable order.
    pub fn all() -> &'static [SafeSearchEngine] {
        &[
            SafeSearchEngine::Google,
            SafeSearchEngine::Bing,
            SafeSearchEngine::YouTube,
            SafeSearchEngine::DuckDuckGo,
            SafeSearchEngine::Yandex,
            SafeSearchEngine::Brave,
            SafeSearchEngine::Ecosia,
        ]
    }
}

impl std::str::FromStr for SafeSearchEngine {
    type Err = UnknownSafeSearchEngine;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "google" => Ok(SafeSearchEngine::Google),
            "bing" => Ok(SafeSearchEngine::Bing),
            "youtube" => Ok(SafeSearchEngine::YouTube),
            "duckduckgo" => Ok(SafeSearchEngine::DuckDuckGo),
            "yandex" => Ok(SafeSearchEngine::Yandex),
            "brave" => Ok(SafeSearchEngine::Brave),
            "ecosia" => Ok(SafeSearchEngine::Ecosia),
            _ => Err(UnknownSafeSearchEngine(s.to_owned())),
        }
    }
}

/// Restriction level applied to YouTube queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YouTubeMode {
    /// Blocks most restricted content. Recommended for younger children.
    #[default]
    Strict,
    /// Allows some age-restricted content. Suitable for teenagers.
    Moderate,
}

impl YouTubeMode {
    /// Returns the canonical lowercase string representation used in the database and API.
    pub fn to_str(self) -> &'static str {
        match self {
            YouTubeMode::Strict => "strict",
            YouTubeMode::Moderate => "moderate",
        }
    }
}

impl std::str::FromStr for YouTubeMode {
    type Err = UnknownYouTubeMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(YouTubeMode::Strict),
            "moderate" => Ok(YouTubeMode::Moderate),
            _ => Err(UnknownYouTubeMode(s.to_owned())),
        }
    }
}

/// Per-group Safe Search configuration for a single search engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeSearchConfig {
    /// Database row identifier. `None` before first persist.
    pub id: Option<i64>,
    /// The group this configuration applies to.
    pub group_id: i64,
    /// The search engine this configuration controls.
    pub engine: SafeSearchEngine,
    /// Whether Safe Search is active for this engine and group.
    pub enabled: bool,
    /// YouTube restriction level. Only relevant when `engine == YouTube`.
    pub youtube_mode: YouTubeMode,
    /// ISO-8601 creation timestamp. `None` before first persist.
    pub created_at: Option<String>,
    /// ISO-8601 last-update timestamp. `None` before first persist.
    pub updated_at: Option<String>,
}
