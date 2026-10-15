use crate::dns::cache::key::normalize_domain;
use ferrous_dns_domain::{DomainError, UpstreamPool};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

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
}

/// The pools claiming one routed domain.
#[derive(Default)]
struct DomainRoutes {
    every_client: Option<usize>,
    by_group: SmallVec<[(u32, usize); 2]>,
}

/// Which pool answers each routed domain, indexed by position in the pool
/// set it was built from. Keys are config, so the Fx hasher is safe here.
#[derive(Default)]
pub(super) struct PoolRoutes {
    by_domain: FxHashMap<Box<str>, DomainRoutes>,
    internal: Vec<bool>,
    has_group_routes: bool,
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
        Ok(routes)
    }

    pub(super) fn has_group_routes(&self) -> bool {
        self.has_group_routes
    }

    /// The pool and route for `domain`. The most specific routed domain
    /// wins; at that domain a route for the client's group wins over one for
    /// every client, and a domain only other groups route is skipped.
    pub(super) fn lookup(&self, domain: &str, group: Option<i64>) -> Option<(usize, Route)> {
        if self.by_domain.is_empty() {
            return None;
        }
        let normalized = normalize_domain(domain);
        let mut name = normalized.strip_suffix('.').unwrap_or(&normalized);
        let group = group.and_then(|id| u32::try_from(id).ok());
        loop {
            if let Some(routes) = self.by_domain.get(name) {
                let scoped = group.and_then(|group| {
                    routes
                        .by_group
                        .iter()
                        .find(|(g, _)| *g == group)
                        .map(|(_, index)| (*index, group))
                });
                if let Some((index, view)) = scoped.or(routes.every_client.map(|index| (index, 0)))
                {
                    let internal = self.internal[index];
                    return Some((index, Route { view, internal }));
                }
            }
            let (_, parent) = name.split_once('.')?;
            name = parent;
        }
    }
}
