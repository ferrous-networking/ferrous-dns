#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file {0}: {1}")]
    FileRead(String, String),

    #[error("Failed to write config file {0}: {1}")]
    FileWrite(String, String),

    #[error("Failed to parse config: {0}")]
    Parse(String),

    #[error("Configuration validation error: {0}")]
    Validation(String),
}
