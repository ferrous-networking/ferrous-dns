use ferrous_dns_domain::Config;

/// Port for persisting Config to a file (TOML).
pub trait ConfigFilePersistence: Send + Sync {
    fn save_config_to_file(&self, config: &Config, path: &str) -> Result<(), String>;
}
