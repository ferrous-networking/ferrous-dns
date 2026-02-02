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
        use hickory_proto::rr::RecordType as HickoryRecordType;

        match query.record_type {
            // IP-based records
            RecordType::A => {
                self.resolve_ip_records(
                    &query.domain,
                    "A",
                    self.resolver.ipv4_lookup(&query.domain),
                    |r| IpAddr::V4(r.0),
                )
                .await
            }

            RecordType::AAAA => {
                self.resolve_ip_records(
                    &query.domain,
                    "AAAA",
                    self.resolver.ipv6_lookup(&query.domain),
                    |r| IpAddr::V6(r.0),
                )
                .await
            }

            // Non-IP records
            RecordType::MX => {
                self.resolve_non_ip_records(&query.domain, "MX", HickoryRecordType::MX)
                    .await
            }
            RecordType::TXT => {
                self.resolve_non_ip_records(&query.domain, "TXT", HickoryRecordType::TXT)
                    .await
            }
            RecordType::CNAME => {
                self.resolve_non_ip_records(&query.domain, "CNAME", HickoryRecordType::CNAME)
                    .await
            }
            RecordType::PTR => {
                self.resolve_non_ip_records(&query.domain, "PTR", HickoryRecordType::PTR)
                    .await
            }
            RecordType::SRV => {
                self.resolve_non_ip_records(&query.domain, "SRV", HickoryRecordType::SRV)
                    .await
            }
            RecordType::SOA => {
                self.resolve_non_ip_records(&query.domain, "SOA", HickoryRecordType::SOA)
                    .await
            }
            RecordType::NS => {
                self.resolve_non_ip_records(&query.domain, "NS", HickoryRecordType::NS)
                    .await
            }
            RecordType::NAPTR => {
                self.resolve_non_ip_records(&query.domain, "NAPTR", HickoryRecordType::NAPTR)
                    .await
            }
            RecordType::DS => {
                self.resolve_non_ip_records(&query.domain, "DS", HickoryRecordType::DS)
                    .await
            }
            RecordType::DNSKEY => {
                self.resolve_non_ip_records(&query.domain, "DNSKEY", HickoryRecordType::DNSKEY)
                    .await
            }
            RecordType::SVCB => {
                self.resolve_non_ip_records(&query.domain, "SVCB", HickoryRecordType::SVCB)
                    .await
            }
            RecordType::HTTPS => {
                self.resolve_non_ip_records(&query.domain, "HTTPS", HickoryRecordType::HTTPS)
                    .await
            }

            // Security & Modern records
            RecordType::CAA => {
                self.resolve_non_ip_records(&query.domain, "CAA", HickoryRecordType::CAA)
                    .await
            }
            RecordType::TLSA => {
                self.resolve_non_ip_records(&query.domain, "TLSA", HickoryRecordType::TLSA)
                    .await
            }
            RecordType::SSHFP => {
                self.resolve_non_ip_records(&query.domain, "SSHFP", HickoryRecordType::SSHFP)
                    .await
            }

            // Note: DNAME not available in Hickory 0.25
            RecordType::DNAME => {
                debug!(domain = %query.domain, "DNAME not supported in Hickory 0.25");
                Ok(vec![])
            }

            // DNSSEC records
            RecordType::RRSIG => {
                self.resolve_non_ip_records(&query.domain, "RRSIG", HickoryRecordType::RRSIG)
                    .await
            }
            RecordType::NSEC => {
                self.resolve_non_ip_records(&query.domain, "NSEC", HickoryRecordType::NSEC)
                    .await
            }
            RecordType::NSEC3 => {
                self.resolve_non_ip_records(&query.domain, "NSEC3", HickoryRecordType::NSEC3)
                    .await
            }
            RecordType::NSEC3PARAM => {
                self.resolve_non_ip_records(
                    &query.domain,
                    "NSEC3PARAM",
                    HickoryRecordType::NSEC3PARAM,
                )
                .await
            }

            // Child DNSSEC
            RecordType::CDS => {
                self.resolve_non_ip_records(&query.domain, "CDS", HickoryRecordType::CDS)
                    .await
            }
            RecordType::CDNSKEY => {
                self.resolve_non_ip_records(&query.domain, "CDNSKEY", HickoryRecordType::CDNSKEY)
                    .await
            }
        }
    }
}

impl HickoryDnsResolver {
    async fn resolve_ip_records<Fut, Resp, Item, Map>(
        &self,
        domain: &str,
        record_name: &'static str,
        fut: Fut,
        map: Map,
    ) -> Result<Vec<IpAddr>, DomainError>
    where
        Fut: std::future::Future<Output = Result<Resp, hickory_resolver::ResolveError>>,
        Resp: IntoIterator<Item = Item>,
        Map: Fn(Item) -> IpAddr,
    {
        match fut.await {
            Ok(response) => {
                let ips: Vec<IpAddr> = response.into_iter().map(map).collect();
                debug!(domain = %domain, count = ips.len(), "{record_name} records resolved");
                Ok(ips)
            }
            Err(e) => handle_no_records_error(domain, record_name, e),
        }
    }

    async fn resolve_non_ip_records(
        &self,
        domain: &str,
        record_name: &'static str,
        record_type: hickory_proto::rr::RecordType,
    ) -> Result<Vec<IpAddr>, DomainError> {
        match self.resolver.lookup(domain, record_type).await {
            Ok(lookup) => {
                let count = lookup.record_iter().count();

                if count > 0 {
                    debug!(domain = %domain, count, "{record_name} records found");
                } else {
                    debug!(domain = %domain, "No {record_name} records found");
                }

                Ok(vec![]) // Server will build response from upstream
            }
            Err(e) => handle_no_records_error(domain, record_name, e),
        }
    }
}

fn handle_no_records_error(
    domain: &str,
    record_type: &str,
    e: impl std::fmt::Display,
) -> Result<Vec<IpAddr>, DomainError> {
    let error_msg = e.to_string();
    if error_msg.contains("no records found")
        || error_msg.contains("no records")
        || error_msg.contains("NoRecordsFound")
    {
        debug!(domain = %domain, "No {} records found", record_type);
        Ok(vec![])
    } else {
        warn!(domain = %domain, error = %e, "{} lookup failed", record_type);
        Err(DomainError::InvalidDomainName(e.to_string()))
    }
}
