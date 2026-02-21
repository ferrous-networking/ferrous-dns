use async_trait::async_trait;
use ferrous_dns_application::ports::HostnameResolver;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::rr::RData;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

use crate::dns::load_balancer::PoolManager;

pub struct PtrHostnameResolver {
    pool_manager: Arc<PoolManager>,
    timeout_secs: u64,
}

impl PtrHostnameResolver {
    pub fn new(pool_manager: Arc<PoolManager>, timeout_secs: u64) -> Self {
        Self {
            pool_manager,
            timeout_secs,
        }
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
}

#[async_trait]
impl HostnameResolver for PtrHostnameResolver {
    async fn resolve_hostname(&self, ip: IpAddr) -> Result<Option<String>, DomainError> {
        let reverse_domain = Self::ip_to_reverse_domain(&ip);

        debug!(
            ip = %ip,
            reverse_domain = %reverse_domain,
            "Performing PTR lookup"
        );

        let timeout_ms = self.timeout_secs * 1000;

        match self
            .pool_manager
            .query(&reverse_domain, &RecordType::PTR, timeout_ms, false)
            .await
        {
            Ok(result) => {
                for record in &result.response.raw_answers {
                    if let RData::PTR(ptr) = record.data() {
                        let hostname = ptr.to_utf8();
                        debug!(
                            ip = %ip,
                            hostname = %hostname,
                            "PTR lookup successful"
                        );
                        return Ok(Some(hostname));
                    }
                }

                debug!(ip = %ip, "PTR lookup returned no records");
                Ok(None)
            }
            Err(e) => {
                debug!(
                    ip = %ip,
                    error = %e,
                    reverse_domain = %reverse_domain,
                    "PTR lookup failed"
                );
                Ok(None)
            }
        }
    }
}
