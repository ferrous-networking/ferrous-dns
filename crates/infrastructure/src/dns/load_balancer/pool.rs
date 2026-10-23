use super::health::HealthChecker;
use super::health::HealthProbe;
use super::query::{all_servers_failed, is_servfail};
use super::routes::{PoolRoutes, Route, UpstreamRouter};
use super::strategy::{QueryContext, ServerDisplays, Strategy, UpstreamResult};
use crate::dns::forwarding::{HardeningOpts, MessageBuilder, ResponseParser, ResponseValidator};
use crate::dns::transport;
use crate::dns::transport::resolver::UpstreamHostResolver;
use arc_swap::ArcSwap;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType, UpstreamPool, UpstreamStrategy};
use smallvec::SmallVec;
use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// Resolved addresses kept per family when a hostname upstream is expanded.
const MAX_ADDRS_PER_FAMILY: usize = 4;

/// The addresses a configured server is reached at, in any order.
fn addresses_of(group: &ServerGroup) -> BTreeSet<SocketAddr> {
    group
        .protocols
        .iter()
        .flat_map(|protocol| match &**protocol {
            DnsProtocol::Https { resolved_addrs, .. } | DnsProtocol::H3 { resolved_addrs, .. } => {
                resolved_addrs.clone()
            }
            other => other.socket_addr().into_iter().collect(),
        })
        .collect()
}

pub struct PoolManager {
    /// Live set of pools, swappable at runtime so upstream changes apply without a restart.
    pools: ArcSwap<PoolSet>,
    /// Whether some pool is routed for a client group, so the cache's per-query
    /// view lookup costs one atomic load for everyone who routes nothing per group.
    /// Never false while the live set holds a group route.
    has_group_routes: Arc<AtomicBool>,
    health_checker: Option<Arc<HealthChecker>>,
    /// Anti-spoofing hardening applied to upstream queries of every record type
    /// (DNS Cookies + 0x20).
    hardening: HardeningOpts,
    /// Set while no server is marked healthy, so each transition is logged once.
    failing_open: AtomicBool,
    /// Looks up hostname upstreams when the pools are built, reloaded or refreshed.
    host_resolver: UpstreamHostResolver,
    /// Signalled by every reload, so the hostname refresh task arms the
    /// servers it brought.
    reloaded: Arc<Notify>,
}

/// Maps one original configured server string to its resolved protocol entries.
#[derive(Clone)]
pub struct ServerGroup {
    pub original: Arc<str>,
    pub protocols: Vec<Arc<DnsProtocol>>,
    pub resolution: Resolution,
}

/// What the last lookup of a configured server's hostname found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The server is given by address: there is nothing to look up.
    Literal,
    /// Resolved, with the answer's TTL when the resolver reported one.
    Resolved { ttl: Option<u32> },
    /// The lookup failed. The server keeps what an earlier lookup found, if
    /// anything.
    Failed,
}

struct PoolWithStrategy {
    config: UpstreamPool,
    strategy: Strategy,
    server_protocols: Vec<Arc<DnsProtocol>>,
    server_groups: Vec<ServerGroup>,
    name_arc: Arc<str>,
    server_displays: ServerDisplays,
    /// The zone a conditional pool's servers are health-checked with: they
    /// may refuse any name outside their own domains.
    probe_zone: Option<Arc<str>>,
}

/// The live pools and the routing built from them, swapped as one so a route
/// never points into another set.
struct PoolSet {
    pools: Vec<PoolWithStrategy>,
    routes: PoolRoutes,
    /// Pools without domains, in priority order: the walk every name no
    /// conditional pool answers takes.
    default_pools: Vec<usize>,
}

/// Why a pool produced no answer.
enum PoolFailure {
    /// An error no lower-priority pool could do better on.
    Final(DomainError),
    /// A transport failure or a declined question, so a lower-priority pool
    /// may still answer. `servfail` is whether every server answered SERVFAIL.
    FellThrough { servfail: bool },
}

impl PoolWithStrategy {
    async fn query(
        &self,
        servers: &[&Arc<DnsProtocol>],
        domain: &str,
        timeout_ms: u64,
        query_bytes: &[u8],
        validator: &ResponseValidator,
    ) -> Result<UpstreamResult, PoolFailure> {
        let ctx = QueryContext {
            servers,
            domain,
            timeout_ms,
            query_bytes,
            validator,
            pool_name: &self.name_arc,
            server_displays: &self.server_displays,
        };
        match self.strategy.query_refs(&ctx).await {
            Ok(result) => {
                debug!(pool = %self.config.name, server = %result.server_display, "Pool query successful");
                Ok(result)
            }
            Err(e) if ResponseParser::is_transport_error(&e) => {
                warn!(pool = %self.config.name, error = %e, "Transport error, trying next pool");
                Err(PoolFailure::FellThrough { servfail: false })
            }
            Err(
                e @ (DomainError::UpstreamServerFailure { .. } | DomainError::AllUpstreamsServfail),
            ) => {
                debug!(pool = %self.config.name, error = %e, "Upstream declined the query, trying next pool");
                Err(PoolFailure::FellThrough {
                    servfail: is_servfail(&e),
                })
            }
            Err(e) => {
                warn!(pool = %self.config.name, error = %e, "DNS error, not trying other pools");
                Err(PoolFailure::Final(e))
            }
        }
    }
}

/// An opaque, fully-rebuilt pool set produced by [`PoolManager::prepare`] and ready
/// to be committed with [`PoolManager::apply`].
pub struct PreparedPools(PoolSet);

impl PoolManager {
    /// Looks upstream hostnames up with the system resolver only.
    pub async fn new(
        pools: Vec<UpstreamPool>,
        health_checker: Option<Arc<HealthChecker>>,
    ) -> Result<Self, DomainError> {
        Self::with_host_resolver(pools, health_checker, UpstreamHostResolver::system()).await
    }

    /// `host_resolver` is used for every lookup: at build, on reload and on refresh.
    pub async fn with_host_resolver(
        pools: Vec<UpstreamPool>,
        health_checker: Option<Arc<HealthChecker>>,
        host_resolver: UpstreamHostResolver,
    ) -> Result<Self, DomainError> {
        let pool_set = Self::build_pools(pools, &host_resolver, false, None).await?;

        Ok(Self {
            has_group_routes: Arc::new(AtomicBool::new(pool_set.routes.has_group_routes())),
            pools: ArcSwap::from_pointee(pool_set),
            health_checker,
            hardening: HardeningOpts::default(),
            failing_open: AtomicBool::new(false),
            host_resolver,
            reloaded: Arc::new(Notify::new()),
        })
    }

    /// Overrides the anti-spoofing hardening applied to upstream queries.
    /// Used by wiring to honor the `qname_case_randomization` config flag.
    pub fn with_hardening(mut self, hardening: HardeningOpts) -> Self {
        self.hardening = hardening;
        self
    }

    /// The hardening applied to upstream queries — shared with the
    /// `local_dns_server` forwarder so both honor the same flags.
    pub fn hardening(&self) -> HardeningOpts {
        self.hardening
    }

    /// Rebuilds the pool set from `pools` and atomically swaps it into the live
    /// query path. New servers are usable immediately; the health-check probe loop
    /// reads the live set each tick, so they also start being probed without a restart.
    pub async fn reload(&self, pools: Vec<UpstreamPool>) -> Result<(), DomainError> {
        let prepared = self.prepare(pools).await?;
        self.apply(prepared);
        Ok(())
    }

    /// Rebuilds the pool set without touching the live query path. Pair with
    /// [`PoolManager::apply`] to stage a fallible rebuild before committing it, so
    /// several managers can be swapped together only once all rebuilds succeed.
    pub async fn prepare(&self, pools: Vec<UpstreamPool>) -> Result<PreparedPools, DomainError> {
        let live = self.pools.load_full();
        Ok(PreparedPools(
            Self::build_pools(pools, &self.host_resolver, false, Some(&live)).await?,
        ))
    }

    /// Atomically swaps a previously [`prepared`](PoolManager::prepare) pool set into
    /// the live query path. Infallible — the fallible work happened in `prepare`.
    pub fn apply(&self, prepared: PreparedPools) {
        let has_group_routes = prepared.0.routes.has_group_routes();
        if has_group_routes {
            self.has_group_routes.store(true, Ordering::Release);
        }
        self.pools.store(Arc::new(prepared.0));
        if !has_group_routes {
            self.has_group_routes.store(false, Ordering::Release);
        }
        self.reloaded.notify_one();
        info!(
            "Upstream pools reloaded ({} pools)",
            self.pools.load().pools.len()
        );
    }

    /// Signalled by every reload: see [`PoolManager::hostname_servers`].
    pub fn reloaded(&self) -> Arc<Notify> {
        Arc::clone(&self.reloaded)
    }

    /// Whether applying `prepared` would route some name differently than
    /// the live set does.
    pub fn routing_changes(&self, prepared: &PreparedPools) -> bool {
        self.pools.load().routes.differs_from(&prepared.0.routes)
    }

    /// The live servers given by hostname, each once, with what the lookup
    /// that built the live set found for them. A reload changes them;
    /// [`PoolManager::reloaded`] says when.
    pub fn hostname_servers(&self) -> Vec<(Arc<str>, Resolution)> {
        let set = self.pools.load();
        let mut seen = HashSet::new();
        set.pools
            .iter()
            .flat_map(|p| &p.server_groups)
            .filter(|g| g.resolution != Resolution::Literal)
            .filter(|g| seen.insert(Arc::clone(&g.original)))
            .map(|g| (Arc::clone(&g.original), g.resolution))
            .collect()
    }

    /// Looks the hostname of the configured server `original` up again. New
    /// addresses replace the old ones in every pool that lists it; each pool
    /// looked it up on its own, so any copy that differs counts. A failed
    /// lookup keeps them. The swap is skipped if a reload replaced the set
    /// meanwhile, since a reload does its own lookups. Returns what the lookup
    /// found, or `None` when no live pool lists `original` any more.
    pub async fn refresh_hostname(&self, original: &str) -> Option<Resolution> {
        let current = self.pools.load_full();
        let copies: Vec<&ServerGroup> = current
            .pools
            .iter()
            .flat_map(|p| &p.server_groups)
            .filter(|g| &*g.original == original)
            .collect();
        let first = copies.first()?;
        let protocol = original.parse::<DnsProtocol>().ok()?;
        let new = Self::expand_hostnames(
            vec![(Arc::clone(&first.original), protocol)],
            &self.host_resolver,
            true,
            Some(&current),
        )
        .await
        .pop()?;
        let new_addresses = addresses_of(&new);
        if copies
            .iter()
            .all(|copy| addresses_of(copy) == new_addresses)
        {
            return Some(new.resolution);
        }
        let patched = current
            .pools
            .iter()
            .map(|p| {
                let groups = p
                    .server_groups
                    .iter()
                    .map(|g| {
                        if g.original == new.original {
                            new.clone()
                        } else {
                            g.clone()
                        }
                    })
                    .collect();
                (p.config.clone(), groups)
            })
            .collect();
        let patched = match Self::assemble(patched) {
            Ok(patched) => patched,
            Err(e) => {
                // Unexpected: the configs are the live set's, which assembled once.
                warn!(server = original, error = %e, "Could not apply an upstream hostname's new addresses");
                return Some(new.resolution);
            }
        };
        let previous = self.pools.compare_and_swap(&current, Arc::new(patched));
        if Arc::ptr_eq(&*previous, &current) {
            info!(
                server = original,
                addresses = ?new_addresses,
                "Upstream hostname now resolves to new addresses"
            );
            let replaced: HashSet<&Arc<DnsProtocol>> =
                copies.iter().flat_map(|copy| &copy.protocols).collect();
            for gone in replaced.into_iter().filter(|p| !new.protocols.contains(p)) {
                transport::forget_transport(gone);
            }
        }
        Some(new.resolution)
    }

    /// `background` marks a lookup the refresh task made: it logs at debug.
    /// A server whose lookup fails keeps what it had in `previous`.
    async fn build_pools(
        pools: Vec<UpstreamPool>,
        host_resolver: &UpstreamHostResolver,
        background: bool,
        previous: Option<&PoolSet>,
    ) -> Result<PoolSet, DomainError> {
        if pools.is_empty() {
            return Err(DomainError::ConfigError(
                "At least one pool must be configured".into(),
            ));
        }
        if pools.iter().all(UpstreamPool::is_conditional) {
            return Err(DomainError::ConfigError(
                "At least one pool must have no domains, to answer every other query".into(),
            ));
        }

        let mut expanded = Vec::with_capacity(pools.len());
        for pool in pools {
            let parsed = pool
                .servers
                .iter()
                .map(|s| Ok((Arc::from(s.as_str()), s.parse::<DnsProtocol>()?)))
                .collect::<Result<Vec<_>, DomainError>>()?;
            let server_groups =
                Self::expand_hostnames(parsed, host_resolver, background, previous).await;
            expanded.push((pool, server_groups));
        }
        Self::assemble(expanded)
    }

    /// Builds a pool set from each pool's config and its expanded servers.
    fn assemble(pools: Vec<(UpstreamPool, Vec<ServerGroup>)>) -> Result<PoolSet, DomainError> {
        let mut pools_with_strategy = Vec::with_capacity(pools.len());
        for (pool, server_groups) in pools {
            let strategy = Strategy::new(pool.strategy);
            let name_arc: Arc<str> = Arc::from(pool.name.as_str());
            let server_protocols: Vec<Arc<DnsProtocol>> = server_groups
                .iter()
                .flat_map(|g| g.protocols.iter().cloned())
                .collect();
            let server_displays: ServerDisplays = server_protocols
                .iter()
                .map(|p| (Arc::clone(p), Arc::from(p.to_string())))
                .collect();
            let probe_zone = pool.normalized_domains()?.into_iter().next().map(Arc::from);
            pools_with_strategy.push(PoolWithStrategy {
                config: pool,
                strategy,
                server_protocols,
                server_groups,
                name_arc,
                server_displays,
                probe_zone,
            });
        }
        pools_with_strategy.sort_by_key(|p| p.config.priority);

        let configs: Vec<&UpstreamPool> = pools_with_strategy.iter().map(|p| &p.config).collect();
        let routes = PoolRoutes::build(&configs)?;
        let default_pools = configs
            .iter()
            .enumerate()
            .filter(|(_, config)| !config.is_conditional())
            .map(|(index, _)| index)
            .collect();

        Ok(PoolSet {
            pools: pools_with_strategy,
            routes,
            default_pools,
        })
    }

    async fn expand_hostnames(
        entries: Vec<(Arc<str>, DnsProtocol)>,
        host_resolver: &UpstreamHostResolver,
        background: bool,
        previous: Option<&PoolSet>,
    ) -> Vec<ServerGroup> {
        let mut groups = Vec::new();
        for (original, protocol) in entries {
            if protocol.needs_resolution() {
                match &protocol {
                    DnsProtocol::Udp { addr }
                    | DnsProtocol::Tcp { addr }
                    | DnsProtocol::Tls { addr, .. }
                    | DnsProtocol::Quic { addr, .. } => {
                        let (hostname, port) = match addr.unresolved_parts() {
                            Some((h, p)) => (h.to_string(), p),
                            None => {
                                groups.push(ServerGroup {
                                    original,
                                    protocols: vec![Arc::new(protocol)],
                                    resolution: Resolution::Literal,
                                });
                                continue;
                            }
                        };
                        match host_resolver
                            .resolve_all(&hostname, port, Duration::from_secs(5))
                            .await
                        {
                            Ok(resolved) => {
                                let limited = Self::limit_resolved_addrs(resolved.addrs);
                                if background {
                                    debug!(%hostname, addresses = ?limited, "Upstream hostname looked up again");
                                } else {
                                    info!(
                                        "{} resolved to {} upstream servers (limited to {} per family)",
                                        hostname,
                                        limited.len(),
                                        MAX_ADDRS_PER_FAMILY,
                                    );
                                }
                                let protocols: Vec<Arc<DnsProtocol>> = limited
                                    .iter()
                                    .map(|addr| {
                                        let resolved = protocol.with_resolved_addr(*addr);
                                        if !background {
                                            info!("  → {}", addr);
                                        }
                                        Arc::new(resolved)
                                    })
                                    .collect();
                                groups.push(ServerGroup {
                                    original,
                                    protocols,
                                    resolution: Resolution::Resolved { ttl: resolved.ttl },
                                });
                            }
                            Err(e) => {
                                let kept = Self::kept_group(previous, &original);
                                if background {
                                    debug!(hostname = %hostname, error = %e, kept_addresses = kept.is_some(), "Upstream hostname lookup failed");
                                } else {
                                    warn!(
                                        hostname = %hostname,
                                        error = %e,
                                        kept_addresses = kept.is_some(),
                                        "Failed to resolve upstream hostname, retrying in the background"
                                    );
                                }
                                groups.push(kept.unwrap_or(ServerGroup {
                                    original,
                                    protocols: vec![Arc::new(protocol)],
                                    resolution: Resolution::Failed,
                                }));
                            }
                        }
                    }
                    DnsProtocol::Https { hostname, port, .. }
                    | DnsProtocol::H3 { hostname, port, .. } => {
                        match host_resolver
                            .resolve_all(hostname, *port, Duration::from_secs(5))
                            .await
                        {
                            Ok(resolved) => {
                                let limited = Self::limit_resolved_addrs(resolved.addrs);
                                if background {
                                    debug!(%hostname, addresses = ?limited, "Upstream hostname looked up again");
                                } else {
                                    info!(
                                        "{} pre-resolved to {} addresses",
                                        hostname,
                                        limited.len()
                                    );
                                    for addr in &limited {
                                        info!("  → {}", addr);
                                    }
                                }
                                groups.push(ServerGroup {
                                    original,
                                    protocols: vec![Arc::new(
                                        protocol.with_resolved_addrs(limited),
                                    )],
                                    resolution: Resolution::Resolved { ttl: resolved.ttl },
                                });
                            }
                            Err(e) => {
                                let kept = Self::kept_group(previous, &original);
                                if background {
                                    debug!(hostname = %hostname, error = %e, kept_addresses = kept.is_some(), "Upstream hostname lookup failed");
                                } else {
                                    warn!(
                                        hostname = %hostname,
                                        error = %e,
                                        kept_addresses = kept.is_some(),
                                        "Failed to pre-resolve, transport will resolve at runtime"
                                    );
                                }
                                groups.push(kept.unwrap_or(ServerGroup {
                                    original,
                                    protocols: vec![Arc::new(protocol)],
                                    resolution: Resolution::Failed,
                                }));
                            }
                        }
                    }
                }
            } else {
                groups.push(ServerGroup {
                    original,
                    protocols: vec![Arc::new(protocol)],
                    resolution: Resolution::Literal,
                });
            }
        }
        groups
    }

    /// What an earlier lookup of `original` gave it in `previous`, kept when
    /// looking it up again fails: those addresses most likely still work.
    fn kept_group(previous: Option<&PoolSet>, original: &Arc<str>) -> Option<ServerGroup> {
        previous?
            .pools
            .iter()
            .flat_map(|p| &p.server_groups)
            .find(|g| g.original == *original && g.protocols.iter().any(|p| !p.needs_resolution()))
            .map(|g| ServerGroup {
                resolution: Resolution::Failed,
                ..g.clone()
            })
    }

    fn limit_resolved_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let mut ipv4_count = 0usize;
        let mut ipv6_count = 0usize;
        addrs
            .into_iter()
            .filter(|addr| {
                if addr.is_ipv4() && ipv4_count < MAX_ADDRS_PER_FAMILY {
                    ipv4_count += 1;
                    true
                } else if addr.is_ipv6() && ipv6_count < MAX_ADDRS_PER_FAMILY {
                    ipv6_count += 1;
                    true
                } else {
                    false
                }
            })
            .collect()
    }

    /// Resolves `domain` as a client outside every group would: through a
    /// conditional pool routed for every client, or else the default pools.
    /// The DNSSEC chain walk uses this, so a routed zone's keys come from the
    /// same resolvers as its answers.
    pub async fn query(
        &self,
        domain: &Arc<str>,
        record_type: &RecordType,
        timeout_ms: u64,
        dnssec_ok: bool,
    ) -> Result<UpstreamResult, DomainError> {
        self.query_for(None, domain, record_type, timeout_ms, dnssec_ok)
            .await
    }

    /// Resolves `domain` through the conditional pool routed for it — for
    /// `group`, else for every client — or else through the default pools
    /// in priority order. A routed name is never asked anywhere else: when
    /// its pool fails, the query fails.
    pub async fn query_for(
        &self,
        group: Option<i64>,
        domain: &Arc<str>,
        record_type: &RecordType,
        timeout_ms: u64,
        dnssec_ok: bool,
    ) -> Result<UpstreamResult, DomainError> {
        // Own the snapshot (load_full) rather than holding a Guard across the
        // upstream await — a long-lived Guard pins an arc_swap slot and slows reloads.
        let set = self.pools.load_full();
        let routed = set.routes.lookup(domain, group);
        // An internal zone is unsigned: asking it for DNSSEC records only
        // grows its answers.
        let dnssec_ok = dnssec_ok && !routed.is_some_and(|(_, route)| route.internal);

        let (query_bytes, validator) =
            MessageBuilder::build_query_hardened(domain, record_type, dnssec_ok, self.hardening)?;

        match routed {
            Some((index, route)) => {
                let mut result = self
                    .query_routed(
                        &set.pools[index],
                        domain,
                        timeout_ms,
                        &query_bytes,
                        &validator,
                    )
                    .await?;
                result.internal = route.internal;
                Ok(result)
            }
            None => {
                self.query_default(&set, domain, timeout_ms, &query_bytes, &validator)
                    .await
            }
        }
    }

    fn healthy_servers<'a>(
        &self,
        pool: &'a PoolWithStrategy,
    ) -> SmallVec<[&'a Arc<DnsProtocol>; 16]> {
        match &self.health_checker {
            Some(checker) => pool
                .server_protocols
                .iter()
                .filter(|p| checker.is_healthy(p))
                .collect(),
            None => pool.server_protocols.iter().collect(),
        }
    }

    async fn query_routed(
        &self,
        pool: &PoolWithStrategy,
        domain: &str,
        timeout_ms: u64,
        query_bytes: &[u8],
        validator: &ResponseValidator,
    ) -> Result<UpstreamResult, DomainError> {
        debug!(pool = %pool.config.name, %domain, "Querying conditional pool");
        let mut servers = self.healthy_servers(pool);
        // Fail open within the pool, as the default walk does across pools.
        if servers.is_empty() {
            servers = pool.server_protocols.iter().collect();
        }
        if servers.is_empty() {
            return Err(all_servers_failed(false));
        }
        match pool
            .query(&servers, domain, timeout_ms, query_bytes, validator)
            .await
        {
            Ok(result) => Ok(result),
            Err(PoolFailure::Final(e)) => Err(e),
            Err(PoolFailure::FellThrough { servfail }) => Err(all_servers_failed(servfail)),
        }
    }

    async fn query_default(
        &self,
        set: &PoolSet,
        domain: &str,
        timeout_ms: u64,
        query_bytes: &[u8],
        validator: &ResponseValidator,
    ) -> Result<UpstreamResult, DomainError> {
        debug!(
            total_pools = set.default_pools.len(),
            %domain, "Starting load balancer query"
        );
        let pools = || set.default_pools.iter().map(|&index| &set.pools[index]);

        let mut any_healthy = false;
        let mut any_tried = false;
        let mut all_servfail = true;
        for pool in pools() {
            let healthy_refs = self.healthy_servers(pool);

            if healthy_refs.is_empty() {
                debug!(pool = %pool.config.name, "All unhealthy, skipping");
                continue;
            }
            if !any_healthy {
                any_healthy = true;
                self.leave_fail_open();
            }

            match pool
                .query(&healthy_refs, domain, timeout_ms, query_bytes, validator)
                .await
            {
                Ok(result) => return Ok(result),
                Err(PoolFailure::Final(e)) => return Err(e),
                Err(PoolFailure::FellThrough { servfail }) => {
                    any_tried = true;
                    all_servfail &= servfail;
                }
            }
        }

        // Fail open: the checker can lag reality (e.g. a network change after
        // boot), and refusing every query is worse than trying the servers anyway.
        if !any_healthy && self.health_checker.is_some() {
            if !self.failing_open.swap(true, Ordering::Relaxed) {
                warn!("No upstream server is marked healthy; querying all servers anyway");
            }
            for pool in pools() {
                let all_refs: SmallVec<[&Arc<DnsProtocol>; 16]> =
                    pool.server_protocols.iter().collect();
                if all_refs.is_empty() {
                    continue;
                }
                match pool
                    .query(&all_refs, domain, timeout_ms, query_bytes, validator)
                    .await
                {
                    Ok(result) => return Ok(result),
                    Err(PoolFailure::Final(e)) => return Err(e),
                    Err(PoolFailure::FellThrough { servfail }) => {
                        any_tried = true;
                        all_servfail &= servfail;
                    }
                }
            }
        }
        Err(all_servers_failed(any_tried && all_servfail))
    }

    fn leave_fail_open(&self) {
        // The plain load keeps the common never-failed-open path free of a contended RMW.
        if self.failing_open.load(Ordering::Relaxed)
            && self.failing_open.swap(false, Ordering::Relaxed)
        {
            info!("An upstream server is healthy again; resuming health-based selection");
        }
    }

    pub fn get_all_servers(&self) -> Vec<std::net::SocketAddr> {
        self.pools
            .load()
            .pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().filter_map(|p| p.socket_addr()))
            .collect()
    }

    pub fn get_all_arc_protocols(&self) -> Vec<Arc<DnsProtocol>> {
        self.pools
            .load()
            .pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().cloned())
            .collect()
    }

    /// Every server with the zone it is health-checked with: none for a
    /// default pool's servers, the first routed domain for a conditional one's.
    pub fn get_health_probes(&self) -> Vec<HealthProbe> {
        self.pools
            .load()
            .pools
            .iter()
            .flat_map(|p| {
                p.server_protocols
                    .iter()
                    .map(|protocol| (Arc::clone(protocol), p.probe_zone.clone()))
            })
            .collect()
    }

    /// Returns all configured servers grouped by original address, enriched with
    /// their pool name and strategy for health display purposes.
    pub fn get_pool_groups(&self) -> Vec<PoolGroupEntry> {
        self.pools
            .load()
            .pools
            .iter()
            .flat_map(|p| {
                let pool_name = Arc::clone(&p.name_arc);
                let strategy = p.config.strategy;
                p.server_groups.iter().map(move |g| PoolGroupEntry {
                    pool_name: Arc::clone(&pool_name),
                    strategy,
                    original: Arc::clone(&g.original),
                    protocols: g.protocols.clone(),
                })
            })
            .collect()
    }
}

impl UpstreamRouter for PoolManager {
    fn route(&self, domain: &str, group: Option<i64>) -> Option<Route> {
        self.pools
            .load()
            .routes
            .lookup(domain, group)
            .map(|(_, route)| route)
    }

    fn view(&self, domain: &str, group: Option<i64>) -> u32 {
        if group.is_none() || !self.has_group_routes.load(Ordering::Acquire) {
            return 0;
        }
        let set = self.pools.load();
        set.routes
            .lookup(domain, group)
            .map_or(0, |(_, route)| route.view)
    }

    fn group_routes_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.has_group_routes)
    }
}

/// One entry returned by [`PoolManager::get_pool_groups`]: a single configured server
/// together with its pool metadata and the list of resolved IP protocols.
pub struct PoolGroupEntry {
    pub pool_name: Arc<str>,
    pub strategy: UpstreamStrategy,
    pub original: Arc<str>,
    pub protocols: Vec<Arc<DnsProtocol>>,
}
