use ferrous_dns_domain::config::ServerConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Docker gives the probe 3 s; stay inside it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Where the probe reaches this host's web server, in the order it tries them:
/// the loopback when the server listens on every address, else the address it
/// is bound to. A dual-stack listener on `::` answers on 127.0.0.1 too, which
/// still works where IPv6 is off on the loopback; ::1 covers an IPv6-only one.
pub fn resolve_probe_addresses(server: &ServerConfig) -> Vec<SocketAddr> {
    let ips = match server.bind_address {
        IpAddr::V4(v4) if v4.is_unspecified() => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        IpAddr::V6(v6) if v6.is_unspecified() => vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        ip => vec![ip],
    };
    ips.into_iter()
        .map(|ip| SocketAddr::new(ip, server.web_port))
        .collect()
}

/// `--healthcheck`: succeeds only when this server's `GET /health` answers
/// 200, i.e. the web server is up and the DNS listener is serving.
pub async fn check_health(server: &ServerConfig) -> anyhow::Result<()> {
    // With web TLS on, plain HTTP is redirected to HTTPS, usually behind a
    // self-signed certificate; the probe only ever talks to this host, never
    // through a proxy from the environment.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()?;
    tokio::time::timeout(
        PROBE_TIMEOUT,
        probe(&client, &resolve_probe_addresses(server)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("no answer within {PROBE_TIMEOUT:?}"))?
}

/// Moves to the next address only when nothing listens on this one.
async fn probe(client: &reqwest::Client, addresses: &[SocketAddr]) -> anyhow::Result<()> {
    let mut refused = None;
    for address in addresses {
        let url = format!("http://{address}/ferrous/api/v1/health");
        let response = match client.get(&url).send().await {
            Ok(response) => response,
            Err(e) if e.is_connect() => {
                refused = Some(e);
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::ensure!(status.is_success(), "{url} answered {status}: {body}");
        println!("{body}");
        return Ok(());
    }
    Err(refused.map_or_else(|| anyhow::anyhow!("no address to probe"), Into::into))
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

    fn addresses(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn test_probe_addresses_use_the_v4_loopback_for_the_unspecified_v4_address() {
        assert_eq!(
            resolve_probe_addresses(&server_on("0.0.0.0")),
            addresses(&["127.0.0.1:8080"])
        );
    }

    #[test]
    fn test_probe_addresses_try_the_v4_loopback_first_for_the_unspecified_v6_address() {
        assert_eq!(
            resolve_probe_addresses(&server_on("::")),
            addresses(&["127.0.0.1:8080", "[::1]:8080"])
        );
    }

    #[test]
    fn test_probe_addresses_keep_a_specific_bind_address() {
        assert_eq!(
            resolve_probe_addresses(&server_on("192.168.1.10")),
            addresses(&["192.168.1.10:8080"])
        );
    }
}
