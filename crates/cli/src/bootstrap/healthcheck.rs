use ferrous_dns_domain::config::ServerConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Docker gives the probe 3 s; stay inside it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Where the probe reaches this host's web server: the loopback when it
/// listens on every address, else the address it is bound to.
pub fn probe_address(server: &ServerConfig) -> SocketAddr {
    let ip = match server.bind_address {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, server.web_port)
}

/// `--healthcheck`: succeeds only when this server's `GET /health` answers
/// 200, i.e. the web server is up and the DNS listener is serving.
pub async fn healthcheck(server: &ServerConfig) -> anyhow::Result<()> {
    let url = format!("http://{}/ferrous/api/v1/health", probe_address(server));
    // With web TLS on, plain HTTP is redirected to HTTPS, usually behind a
    // self-signed certificate; the probe only ever talks to this host.
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&url).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    anyhow::ensure!(status.is_success(), "{url} answered {status}: {body}");
    println!("{body}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_on(bind: &str) -> ServerConfig {
        ServerConfig {
            bind_address: bind.parse().unwrap(),
            web_port: 8080,
            ..ServerConfig::default()
        }
    }

    #[test]
    fn test_probe_address_uses_the_v4_loopback_for_every_v4_address() {
        assert_eq!(
            probe_address(&server_on("0.0.0.0")),
            "127.0.0.1:8080".parse().unwrap()
        );
    }

    #[test]
    fn test_probe_address_uses_the_v6_loopback_for_every_v6_address() {
        assert_eq!(
            probe_address(&server_on("::")),
            "[::1]:8080".parse().unwrap()
        );
    }

    #[test]
    fn test_probe_address_keeps_a_specific_bind_address() {
        assert_eq!(
            probe_address(&server_on("192.168.1.10")),
            "192.168.1.10:8080".parse().unwrap()
        );
    }
}
