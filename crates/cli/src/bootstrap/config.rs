use ferrous_dns_domain::{CliOverrides, Config};
use tracing::info;

pub fn load_config(
    config_path: Option<&str>,
    cli_overrides: CliOverrides,
) -> anyhow::Result<Config> {
    let config = Config::load(config_path, cli_overrides)?;
    config.validate()?;

    info!(
        config_file = config_path.unwrap_or("default"),
        dns_port = config.server.dns_port,
        web_port = config.server.web_port,
        bind = %config.server.bind_address,
        "Configuration loaded"
    );

    Ok(config)
}
