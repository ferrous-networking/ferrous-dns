use async_trait::async_trait;
use ferrous_dns_application::ports::HostnameResolver;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::rr::RData;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

use crate::dns::forwarding::DnsForwarder;
use crate::dns::load_balancer::PoolManager;

pub struct PtrHostnameResolver {
    pool_manager: Arc<PoolManager>,
    timeout_secs: u64,
    local_dns_server: Option<String>,
}

impl PtrHostnameResolver {
    pub fn new(pool_manager: Arc<PoolManager>, timeout_secs: u64) -> Self {
        Self {
            pool_manager,
            timeout_secs,
            local_dns_server: None,
        }
    }

    pub fn with_local_dns_server(mut self, server: Option<String>) -> Self {
        self.local_dns_server = server;
        self
    }

    pub fn ip_to_reverse_domain(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(ipv6) => {
                let mut nibbles = Vec::new();
                for byte in ipv6.octets().iter().rev() {
                    nibbles.push(format!("{:x}", byte & 0x0f));
                    nibbles.push(format!("{:x}", (byte >> 4) & 0x0f));
                }
                format!("{}.ip6.arpa", nibbles.join("."))
            }
        }
    }

    fn is_private_or_local(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        }
    }
}

#[async_trait]
impl HostnameResolver for PtrHostnameResolver {
    async fn resolve_hostname(&self, ip: IpAddr) -> Result<Option<String>, DomainError> {
        let reverse_domain = Self::ip_to_reverse_domain(&ip);
        let timeout_ms = self.timeout_secs * 1000;

        debug!(
            ip = %ip,
            reverse_domain = %reverse_domain,
            "Performing PTR lookup"
        );

        if let Some(ref server) = self.local_dns_server {
            if Self::is_private_or_local(&ip) {
                let forwarder = DnsForwarder::new();
                match forwarder
                    .query(server, &reverse_domain, &RecordType::PTR, timeout_ms)
                    .await
                {
                    Ok(result) => {
                        for record in &result.raw_answers {
                            if let RData::PTR(ptr) = record.data() {
                                let hostname = ptr.to_utf8();
                                debug!(ip = %ip, hostname = %hostname, server = %server, "PTR lookup via local DNS server successful");
                                return Ok(Some(hostname));
                            }
                        }
                        debug!(ip = %ip, server = %server, "PTR lookup via local DNS server returned no records");
                        return Ok(None);
                    }
                    Err(e) => {
                        debug!(ip = %ip, server = %server, error = %e, "PTR lookup via local DNS server failed, falling back to upstream");
                    }
                }
            }
        }

        let domain_arc: Arc<str> = Arc::from(reverse_domain.as_str());
        match self
            .pool_manager
            .query(&domain_arc, &RecordType::PTR, timeout_ms, false)
            .await
        {
            Ok(result) => {
                for record in &result.response.raw_answers {
                    if let RData::PTR(ptr) = record.data() {
                        let hostname = ptr.to_utf8();
                        debug!(ip = %ip, hostname = %hostname, "PTR lookup successful");
                        return Ok(Some(hostname));
                    }
                }

                debug!(ip = %ip, "PTR lookup returned no records");
                Ok(None)
            }
            Err(e) => {
                debug!(ip = %ip, error = %e, reverse_domain = %reverse_domain, "PTR lookup failed");
                Ok(None)
            }
        }
    }
}
