use async_trait::async_trait;
use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;

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
                let response = self
                    .resolver
                    .ipv4_lookup(&query.domain)
                    .await
                    .map_err(|e| DomainError::InvalidDomainName(e.to_string()))?;

                // Extract Ipv4Addr from A record
                Ok(response
                    .iter()
                    .map(|a_record| IpAddr::V4(a_record.0))
                    .collect())
            }
            RecordType::AAAA => {
                let response = self
                    .resolver
                    .ipv6_lookup(&query.domain)
                    .await
                    .map_err(|e| DomainError::InvalidDomainName(e.to_string()))?;

                // Extract Ipv6Addr from AAAA record
                Ok(response
                    .iter()
                    .map(|aaaa_record| IpAddr::V6(aaaa_record.0))
                    .collect())
            }
            _ => {
                // For other record types, return empty for now
                Ok(vec![])
            }
        }
    }
}
