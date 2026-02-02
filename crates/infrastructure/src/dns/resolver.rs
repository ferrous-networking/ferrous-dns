use async_trait::async_trait;
use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use tracing::{debug, warn};

pub struct HickoryDnsResolver {
    resolver: Resolver<TokioConnectionProvider>,
}

impl HickoryDnsResolver {
    /// Create resolver with system configuration
    pub fn new() -> Result<Self, DomainError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver })
    }

    /// Create resolver with Google DNS (8.8.8.8)
    pub fn with_google() -> Result<Self, DomainError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::google(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver })
    }

    /// Create resolver with Cloudflare DNS (1.1.1.1)
    pub fn with_cloudflare() -> Result<Self, DomainError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver })
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<Vec<IpAddr>, DomainError> {
        match query.record_type {
            RecordType::A => {
                match self.resolver.ipv4_lookup(&query.domain).await {
                    Ok(response) => {
                        let ips: Vec<IpAddr> = response
                            .iter()
                            .map(|a_record| IpAddr::V4(a_record.0))
                            .collect();

                        debug!(domain = %query.domain, count = ips.len(), "A records resolved");
                        Ok(ips)
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        // No A records found is not an error, just empty result
                        if error_msg.contains("no records found")
                            || error_msg.contains("no records")
                            || error_msg.contains("NoRecordsFound")
                        {
                            debug!(domain = %query.domain, "No A records found");
                            Ok(vec![])
                        } else {
                            warn!(domain = %query.domain, error = %e, "A lookup failed");
                            Err(DomainError::InvalidDomainName(e.to_string()))
                        }
                    }
                }
            }

            RecordType::AAAA => {
                match self.resolver.ipv6_lookup(&query.domain).await {
                    Ok(response) => {
                        let ips: Vec<IpAddr> = response
                            .iter()
                            .map(|aaaa_record| IpAddr::V6(aaaa_record.0))
                            .collect();

                        debug!(domain = %query.domain, count = ips.len(), "AAAA records resolved");
                        Ok(ips)
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        // No AAAA records found is not an error, just empty result
                        if error_msg.contains("no records found")
                            || error_msg.contains("no records")
                            || error_msg.contains("NoRecordsFound")
                        {
                            debug!(domain = %query.domain, "No AAAA records found");
                            Ok(vec![])
                        } else {
                            warn!(domain = %query.domain, error = %e, "AAAA lookup failed");
                            Err(DomainError::InvalidDomainName(e.to_string()))
                        }
                    }
                }
            }

            RecordType::MX | RecordType::TXT | RecordType::CNAME | RecordType::PTR => {
                // MX, TXT, CNAME and PTR records don't return IP addresses
                // They should be handled differently in the future
                // For now, try A record fallback for the domain
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type.as_str(),
                    "Non-IP record type, attempting A record fallback"
                );

                match self.resolver.ipv4_lookup(&query.domain).await {
                    Ok(response) => {
                        let ips: Vec<IpAddr> = response
                            .iter()
                            .map(|a_record| IpAddr::V4(a_record.0))
                            .collect();
                        Ok(ips)
                    }
                    Err(_) => Ok(vec![]),
                }
            }
        }
    }
}
