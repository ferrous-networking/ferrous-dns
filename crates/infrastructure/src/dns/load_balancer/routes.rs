use ferrous_dns_domain::{DomainError, UpstreamPool};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Longest query name a lookup lowercases on the stack; DNS names stop at 253 bytes.
const MAX_NAME_LEN: usize = 255;

/// The conditional pool route a name takes for one client group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The client group the route is scoped to, which keys its answers in
    /// the cache; 0 for a route every client shares.
    pub view: u32,
    /// The pool answers an internal zone: no DNSSEC validation, no rebinding
    /// protection.
    pub internal: bool,
}

/// Finds the conditional pool that answers a name, for the layers above the
/// upstream query that must know it in advance: the cache and the filters.
pub trait UpstreamRouter: Send + Sync {
    /// `None` when no conditional pool answers `domain` for `group`, so the
    /// default pools do.
    fn route(&self, domain: &str, group: Option<i64>) -> Option<Route>;

    /// The cache view `domain` is stored under for `group`.
    fn view(&self, domain: &str, group: Option<i64>) -> u32 {
        self.route(domain, group).map_or(0, |route| route.view)
    }

    /// Set while some route is scoped to a client group. Readers that only
    /// need [`Self::view`] check it first, so a deployment without group
    /// routes pays one atomic load per query and no lookup.
    fn group_routes_flag(&self) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(true))
    }
}

/// The pools claiming one routed domain. An entry with neither is a parent
/// of a routed domain, there so a lookup knows to look deeper.
#[derive(Default)]
struct DomainRoutes {
    every_client: Option<usize>,
    by_group: SmallVec<[(u32, usize); 2]>,
}

impl DomainRoutes {
    /// The pool and cache view this domain's routes give `group`: its own
    /// route first, then the one for every client.
    fn matching(&self, group: Option<u32>) -> Option<(usize, u32)> {
        group
            .and_then(|group| {
                self.by_group
                    .iter()
                    .find(|(g, _)| *g == group)
                    .map(|(_, index)| (*index, group))
            })
            .or(self.every_client.map(|index| (index, 0)))
    }
}

/// One route as configured: domain, client group (`None` for every client),
/// pool name and whether the pool is internal.
type RouteEntry = (Box<str>, Option<u32>, Box<str>, bool);

/// Which pool answers each routed domain, indexed by position in the pool
/// set it was built from. Keys are config, so the Fx hasher is safe here.
#[derive(Default)]
pub(super) struct PoolRoutes {
    by_domain: FxHashMap<Box<str>, DomainRoutes>,
    internal: Vec<bool>,
    has_group_routes: bool,
    /// Every route the set holds, sorted, so two sets can tell whether a
    /// reload changed where any name goes.
    signature: Vec<RouteEntry>,
}

impl PoolRoutes {
    pub(super) fn build(pools: &[&UpstreamPool]) -> Result<Self, DomainError> {
        let mut routes = Self {
            internal: pools.iter().map(|pool| pool.internal).collect(),
            ..Self::default()
        };
        for (index, pool) in pools.iter().enumerate() {
            let groups = pool
                .groups
                .iter()
                .map(|id| {
                    u32::try_from(*id)
                        .ok()
                        .filter(|id| *id != 0)
                        .ok_or_else(|| {
                            DomainError::ConfigError(format!(
                                "Pool '{}': {id} is not a client group id",
                                pool.name
                            ))
                        })
                })
                .collect::<Result<SmallVec<[u32; 4]>, DomainError>>()?;
            for domain in pool.normalized_domains()? {
                if groups.is_empty() {
                    routes.signature.push((
                        domain.as_str().into(),
                        None,
                        pool.name.as_str().into(),
                        pool.internal,
                    ));
                }
                for group in &groups {
                    routes.signature.push((
                        domain.as_str().into(),
                        Some(*group),
                        pool.name.as_str().into(),
                        pool.internal,
                    ));
                }
                for (dot, _) in domain.match_indices('.') {
                    routes
                        .by_domain
                        .entry(domain[dot + 1..].into())
                        .or_default();
                }
                let entry = routes.by_domain.entry(domain.into_boxed_str()).or_default();
                if groups.is_empty() {
                    entry.every_client.get_or_insert(index);
                }
                for group in &groups {
                    if !entry.by_group.iter().any(|(g, _)| g == group) {
                        entry.by_group.push((*group, index));
                    }
                }
            }
            routes.has_group_routes |= pool.is_conditional() && !groups.is_empty();
        }
        routes.signature.sort();
        routes.signature.dedup();
        Ok(routes)
    }

    pub(super) fn has_group_routes(&self) -> bool {
        self.has_group_routes
    }

    /// Whether some name is routed differently by `other`.
    pub(super) fn differs_from(&self, other: &PoolRoutes) -> bool {
        self.signature != other.signature
    }

    /// The pool and route for `domain`. The most specific routed domain
    /// wins; at that domain a route for the client's group wins over one for
    /// every client, and a domain only other groups route is skipped.
    pub(super) fn lookup(&self, domain: &str, group: Option<i64>) -> Option<(usize, Route)> {
        if self.by_domain.is_empty() {
            return None;
        }
        let name = domain.strip_suffix('.').unwrap_or(domain);
        let mut buf = [0u8; MAX_NAME_LEN];
        let name = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            // Longer than any DNS name, so no route can match it.
            let lowered = buf.get_mut(..name.len())?;
            lowered.copy_from_slice(name.as_bytes());
            lowered.make_ascii_lowercase();
            std::str::from_utf8(lowered).ok()?
        } else {
            name
        };
        let group = group.and_then(|id| u32::try_from(id).ok());

        // From the top-level label down: a suffix the map does not hold has
        // no routed domain under it, so most names stop after one probe.
        let mut best = None;
        let mut prefix_end = name.len();
        loop {
            let start = name[..prefix_end].rfind('.').map_or(0, |dot| dot + 1);
            let Some(routes) = self.by_domain.get(&name[start..]) else {
                break;
            };
            if let Some(found) = routes.matching(group) {
                best = Some(found);
            }
            if start == 0 {
                break;
            }
            prefix_end = start - 1;
        }
        best.map(|(index, view)| {
            let internal = self.internal[index];
            (index, Route { view, internal })
        })
    }
}
