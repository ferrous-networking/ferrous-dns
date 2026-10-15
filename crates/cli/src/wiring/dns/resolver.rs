use anyhow::Context;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::dnssec::{DnssecCache, TrustAnchorStore};
use ferrous_dns_infrastructure::dns::resolver::{NonFqdn, QueryFilters, ResolverBuilder};
use ferrous_dns_infrastructure::dns::PoolManager;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// The resolver layers below the cache. The query path and the cache refresh
/// worker both build on them, so a refreshed entry is validated, synthesized
/// and routed to the local server exactly like a cache miss.
pub(super) struct UpstreamLayers {
    timeout_ms: u64,
    local_domain: Option<String>,
    local_dns_server: Option<SocketAddr>,
    dnssec: Option<Dnssec>,
    dns64_prefix: Option<Ipv6Addr>,
}

struct Dnssec {
    pool_manager: Arc<PoolManager>,
    trust_anchors: TrustAnchorStore,
    cache: Arc<DnssecCache>,
}

impl UpstreamLayers {
    /// Validation is on exactly when a `dnssec_pool_manager` is given.
    pub(super) fn from_config(
        config: &Config,
        dnssec_pool_manager: Option<Arc<PoolManager>>,
        local_dns_server: Option<SocketAddr>,
        timeout_ms: u64,
    ) -> anyhow::Result<Self> {
        let dnssec = match dnssec_pool_manager {
            Some(pool_manager) => Some(Dnssec {
                pool_manager,
                trust_anchors: load_trust_anchors(config)?,
                cache: Arc::new(DnssecCache::new()),
            }),
            None => {
                if config.dns.dnssec_trust_anchor_file.is_some() {
                    debug!("DNSSEC validation is off — dnssec_trust_anchor_file is ignored");
                }
                None
            }
        };

        // DNS64 (RFC 6147) — fail-soft: a malformed / non-/96 prefix disables the
        // feature with a warning rather than refusing to start.
        let dns64_prefix = if config.dns64.enabled {
            let prefix = config.dns64.parsed_prefix();
            match prefix {
                Some(prefix) => info!(prefix = %prefix, "DNS64 AAAA synthesis enabled"),
                None => warn!(
                    prefix = %config.dns64.prefix,
                    "DNS64 enabled but prefix is invalid (only /96 is supported) — DNS64 disabled"
                ),
            }
            prefix
        } else {
            None
        };

        info!(
            dnssec_mode = %config.dns.effective_dnssec_mode(),
            pools = config.dns.pools.len(),
            block_private_ptr = config.dns.block_private_ptr,
            block_non_fqdn = config.dns.block_non_fqdn,
            local_domain = ?config.dns.local_domain,
            local_dns_server = ?local_dns_server,
            "DNS resolver configured"
        );

        Ok(Self {
            timeout_ms,
            local_domain: config.dns.local_domain.clone(),
            local_dns_server,
            dnssec,
            dns64_prefix,
        })
    }

    /// The validator cache when validation is on, so its counters can be reported.
    pub(super) fn dnssec_cache(&self) -> Option<Arc<DnssecCache>> {
        self.dnssec.as_ref().map(|dnssec| Arc::clone(&dnssec.cache))
    }

    /// A builder holding these layers over `pool_manager`.
    pub(super) fn builder(&self, pool_manager: Arc<PoolManager>) -> ResolverBuilder {
        let mut builder = ResolverBuilder::new(pool_manager, self.timeout_ms)
            .with_local_domain(self.local_domain.clone())
            .with_local_dns_server(self.local_dns_server);
        if let Some(dnssec) = &self.dnssec {
            builder = builder.with_dnssec(
                Arc::clone(&dnssec.pool_manager),
                dnssec.trust_anchors.clone(),
                Arc::clone(&dnssec.cache),
            );
        }
        if let Some(prefix) = self.dns64_prefix {
            builder = builder.with_dns64(prefix);
        }
        builder
    }
}

/// The query-path filters: private PTRs and single-label names.
pub(super) fn query_filters(config: &Config, local_dns_server: Option<SocketAddr>) -> QueryFilters {
    let non_fqdn = match (config.dns.block_non_fqdn, &config.dns.local_domain) {
        (true, _) => NonFqdn::Block,
        (false, Some(domain)) => NonFqdn::Qualify(domain.clone()),
        (false, None) => NonFqdn::Pass,
    };
    // A local DNS server answers private PTRs, so they must reach it.
    QueryFilters::new(
        config.dns.block_private_ptr && local_dns_server.is_none(),
        non_fqdn,
    )
}

/// Loads the DNSSEC trust anchors: the operator's file when one is configured,
/// the IANA root anchors embedded in the binary otherwise.
///
/// A configured file that cannot be read or parsed aborts startup instead of
/// falling back to the embedded set — silently keeping the old trust root would
/// leave the operator believing they had replaced it.
fn load_trust_anchors(config: &Config) -> anyhow::Result<TrustAnchorStore> {
    let configured_path = config.dns.dnssec_trust_anchor_file.as_deref();

    let store = match configured_path {
        Some(path) => TrustAnchorStore::from_file(path)
            .with_context(|| format!("failed to load DNSSEC trust anchors from {path}"))?,
        None => TrustAnchorStore::new(),
    };

    info!(
        count = store.len(),
        source = configured_path.unwrap_or("embedded"),
        "DNSSEC trust anchors loaded"
    );

    for anchor in store.iter() {
        debug!(
            zone = %anchor.domain,
            key_tag = anchor.key_tag(),
            algorithm = anchor.algorithm(),
            description = %anchor.description,
            "DNSSEC trust anchor"
        );
    }

    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrous_dns_domain::{DnsQuery, RecordType, UpstreamPool, UpstreamStrategy};
    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record, RecordType as WireRecordType};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    /// Answers every A query with `address` and every other type with NODATA.
    async fn spawn_responder(address: Ipv4Addr) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let Some(question) = request.queries.first().cloned() else {
                    continue;
                };
                let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response.metadata.response_code = ResponseCode::NoError;
                response.add_query(question.clone());
                if question.query_type() == WireRecordType::A {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A(address)),
                    ));
                }
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    /// The cache refresh worker resolves through these layers; before, it used
    /// a bare core resolver, so a refreshed AAAA lost its DNS64 synthesis and a
    /// local-domain name was refreshed from the public upstream.
    #[tokio::test]
    async fn layers_below_the_cache_synthesize_and_route_local_names() {
        let public = Ipv4Addr::new(93, 184, 216, 34);
        let lan_host = Ipv4Addr::new(10, 0, 0, 5);
        let upstream = spawn_responder(public).await;
        let router = spawn_responder(lan_host).await;

        let mut config = Config::default();
        config.dns.local_domain = Some("lan".to_string());
        config.dns64.enabled = true;
        let pool_manager = PoolManager::new(
            vec![UpstreamPool {
                name: "test".into(),
                strategy: UpstreamStrategy::Parallel,
                priority: 1,
                servers: vec![format!("udp://{upstream}")],
                weight: None,
                ..Default::default()
            }],
            None,
        )
        .await
        .unwrap();
        let resolver = UpstreamLayers::from_config(&config, None, Some(router), 2000)
            .unwrap()
            .builder(Arc::new(pool_manager))
            .build();

        let aaaa = resolver
            .resolve(&DnsQuery::new("v4only.example", RecordType::AAAA))
            .await
            .unwrap();
        let synthesized: Ipv6Addr = "64:ff9b::5db8:d822".parse().unwrap();
        assert_eq!(aaaa.addresses.as_ref(), &[IpAddr::V6(synthesized)]);

        let local = resolver
            .resolve(&DnsQuery::new("nas.lan", RecordType::A))
            .await
            .unwrap();
        assert!(local.local_dns);
        assert_eq!(local.addresses.as_ref(), &[IpAddr::V4(lan_host)]);
    }
}
