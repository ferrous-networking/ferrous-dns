use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use ferrous_dns_application::ports::{
    DnsResolution, DnsResolver, PtrRecordRegistry, EMPTY_CNAME_CHAIN,
};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, PrivateIpFilter, RecordType};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, RData};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Concurrent map of IP address → (FQDN, TTL) used for PTR auto-generation.
pub type PtrMap = DashMap<IpAddr, (Arc<str>, u32), FxBuildHasher>;

/// DNS resolver layer that intercepts PTR queries and answers from local record mappings.
///
/// Non-PTR queries pass through to the inner resolver immediately with a single
/// `RecordType` comparison — zero overhead on the A/AAAA hot path.
pub struct LocalPtrResolver {
    inner: Arc<dyn DnsResolver>,
    /// Live mapping of IP address → (FQDN, TTL).
    pub map: Arc<PtrMap>,
}

impl LocalPtrResolver {
    /// Creates a resolver wrapping `inner` with an existing live PTR map.
    pub fn new(inner: Arc<dyn DnsResolver>, map: Arc<PtrMap>) -> Self {
        Self { inner, map }
    }

    /// Builds a resolver pre-populated from local DNS records declared in config.
    pub fn from_local_records(
        records: &[LocalDnsRecord],
        default_domain: &Option<String>,
        inner: Arc<dyn DnsResolver>,
    ) -> Self {
        let map: PtrMap = DashMap::with_hasher(FxBuildHasher);

        let mut count = 0usize;

        for record in records {
            match record.ip.parse::<IpAddr>() {
                Ok(ip) => {
                    let fqdn = record.fqdn(default_domain);
                    map.insert(ip, (Arc::from(fqdn.as_str()), record.ttl_or_default()));
                    count += 1;
                }
                Err(_) => {
                    warn!(
                        hostname = %record.hostname,
                        ip = %record.ip,
                        "PTR auto-generation: invalid IP address, skipping record"
                    );
                }
            }
        }

        info!(
            count,
            "PTR auto-generation: preloaded local records at startup"
        );

        Self {
            inner,
            map: Arc::new(map),
        }
    }
}

impl PtrRecordRegistry for LocalPtrResolver {
    fn register(&self, ip: IpAddr, fqdn: Arc<str>, ttl: u32) {
        self.map.insert(ip, (fqdn, ttl));
    }

    fn unregister(&self, ip: IpAddr) {
        self.map.remove(&ip);
    }
}

#[async_trait]
impl DnsResolver for LocalPtrResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        if query.record_type != RecordType::PTR {
            return self.inner.try_cache(query);
        }
        None
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if query.record_type != RecordType::PTR {
            return self.inner.resolve(query).await;
        }

        let ip = match PrivateIpFilter::extract_ip_from_ptr(&query.domain) {
            Some(ip) => ip,
            None => return self.inner.resolve(query).await,
        };

        if let Some(entry) = self.map.get(&ip) {
            let (fqdn, ttl) = entry.value();
            debug!(
                domain = %query.domain,
                ip = %ip,
                ptr = %fqdn,
                "LocalPtrResolver: PTR answered from local records"
            );
            return match build_ptr_resolution(query, fqdn, *ttl) {
                Some(resolution) => Ok(resolution),
                None => self.inner.resolve(query).await,
            };
        }

        self.inner.resolve(query).await
    }
}

fn build_ptr_resolution(query: &DnsQuery, hostname: &str, ttl: u32) -> Option<DnsResolution> {
    let query_name = Name::from_str(&query.domain)
        .map_err(|e| {
            warn!(domain = %query.domain, error = %e, "PTR: failed to parse query name");
        })
        .ok()?;

    let ptr_name = Name::from_str(hostname)
        .map_err(|e| {
            warn!(hostname = %hostname, error = %e, "PTR: failed to parse PTR hostname");
        })
        .ok()?;

    let record = hickory_proto::rr::Record::from_rdata(query_name, ttl, RData::PTR(PTR(ptr_name)));

    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.set_response_code(ResponseCode::NoError);
    message.set_authoritative(true);
    message.add_answer(record);

    let mut buf = Vec::with_capacity(128);
    let mut encoder = BinEncoder::new(&mut buf);
    message
        .emit(&mut encoder)
        .map_err(|e| {
            warn!(hostname = %hostname, error = %e, "PTR: failed to serialize response");
        })
        .ok()?;

    Some(DnsResolution {
        addresses: Arc::new(Vec::new()),
        cache_hit: false,
        local_dns: true,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: None,
        upstream_pool: None,
        min_ttl: Some(ttl),
        negative_soa_ttl: None,
        upstream_wire_data: Some(Bytes::from(buf)),
    })
}
