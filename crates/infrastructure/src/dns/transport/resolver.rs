use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::time::Duration;

/// Resolves a hostname to all its IP addresses (IPv4 + IPv6).
pub async fn resolve_all(
    hostname: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, DomainError> {
    let target = format!("{}:{}", hostname, port);

    let addrs_iter = tokio::time::timeout(timeout, tokio::net::lookup_host(&target))
        .await
        .map_err(|_| DomainError::TransportTimeout {
            server: target.clone(),
        })?
        .map_err(|e| {
            DomainError::InvalidDomainName(format!("DNS resolution failed for {}: {}", target, e))
        })?;

    let addrs: Vec<SocketAddr> = addrs_iter.collect();

    if addrs.is_empty() {
        return Err(DomainError::InvalidDomainName(format!(
            "No addresses found for {}",
            target
        )));
    }

    Ok(addrs)
}
