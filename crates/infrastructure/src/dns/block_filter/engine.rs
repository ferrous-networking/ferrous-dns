use super::block_index::BlockIndex;
use super::compiler::compile_block_index;
use super::decision_cache::{
    decision_l0_clear, decision_l0_get, decision_l0_set, BlockDecisionCache,
};
use crate::dns::cache::coarse_clock::coarse_now_secs;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::{ClientSubnet, DomainError, SubnetMatcher};
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use sqlx::{Row, SqlitePool};
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{error, info, warn};

type GroupL0Cache = LruCache<IpAddr, (i64, u64), FxBuildHasher>;

thread_local! {
    static GROUP_L0: RefCell<GroupL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(32).unwrap(),
            FxBuildHasher,
        ));
}

pub struct BlockFilterEngine {
    index: ArcSwap<BlockIndex>,
    decision_cache: BlockDecisionCache,
    client_groups: Arc<DashMap<IpAddr, i64, FxBuildHasher>>,
    subnet_matcher: ArcSwap<Option<SubnetMatcher>>,
    default_group_id: i64,
    pool: SqlitePool,
    http_client: reqwest::Client,
}

impl BlockFilterEngine {
    pub async fn new(pool: SqlitePool, default_group_id: i64) -> Result<Self, DomainError> {
        let http_client = reqwest::Client::builder()
            .user_agent("Ferrous-DNS/1.0 (blocklist-sync)")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| DomainError::BlockFilterCompileError(e.to_string()))?;

        info!("Block filter compilation started");
        let index = compile_block_index(&pool, &http_client).await?;
        info!("BlockFilterEngine initialized");

        let engine = Self {
            index: ArcSwap::from_pointee(index),
            decision_cache: BlockDecisionCache::new(),
            client_groups: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            subnet_matcher: ArcSwap::from_pointee(None),
            default_group_id,
            pool,
            http_client,
        };

        engine.load_client_groups_inner().await?;

        Ok(engine)
    }

    fn resolve_group_uncached(&self, ip: IpAddr) -> i64 {
        if let Some(gid) = self.client_groups.get(&ip) {
            return *gid;
        }

        let guard = self.subnet_matcher.load();
        if let Some(matcher) = guard.as_ref() {
            if let Some(gid) = matcher.find_group_for_ip(ip) {
                return gid;
            }
        }

        self.default_group_id
    }

    async fn load_client_groups_inner(&self) -> Result<(), DomainError> {
        let client_rows =
            sqlx::query("SELECT ip_address, group_id FROM clients WHERE group_id IS NOT NULL")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        self.client_groups.clear();
        for row in &client_rows {
            let ip_str: String = row.get("ip_address");
            let group_id: i64 = row.get("group_id");
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.client_groups.insert(ip, group_id);
            }
        }

        let subnet_rows = sqlx::query(
            "SELECT subnet_cidr, group_id FROM client_subnets ORDER BY length(subnet_cidr) DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        let subnets: Vec<ClientSubnet> = subnet_rows
            .iter()
            .map(|row| ClientSubnet {
                id: None,
                subnet_cidr: Arc::from(row.get::<String, _>("subnet_cidr").as_str()),
                group_id: row.get("group_id"),
                comment: None,
                created_at: None,
                updated_at: None,
            })
            .collect();

        let matcher = match SubnetMatcher::new(subnets) {
            Ok(m) => Some(m),
            Err(e) => {
                warn!(error = %e, "Failed to build SubnetMatcher; CIDR-based group lookup disabled");
                None
            }
        };
        self.subnet_matcher.store(Arc::new(matcher));

        info!(clients = client_rows.len(), "Client groups loaded");

        Ok(())
    }
}

#[async_trait]
impl BlockFilterEnginePort for BlockFilterEngine {
    #[inline]
    fn resolve_group(&self, ip: IpAddr) -> i64 {
        if let Some(gid) = GROUP_L0.with(|c| {
            let mut cache = c.borrow_mut();
            if let Some(&(gid, expires)) = cache.get(&ip) {
                if coarse_now_secs() < expires {
                    return Some(gid);
                }
                cache.pop(&ip);
            }
            None
        }) {
            return gid;
        }

        let gid = self.resolve_group_uncached(ip);
        GROUP_L0.with(|c| {
            c.borrow_mut().put(ip, (gid, coarse_now_secs() + 60));
        });
        gid
    }

    #[inline]
    fn check(&self, domain: &str, group_id: i64) -> FilterDecision {
        // L0: thread-local decision cache
        if let Some(cached_source) = decision_l0_get(domain, group_id) {
            return match cached_source {
                Some(source) => FilterDecision::Block(source),
                None => FilterDecision::Allow,
            };
        }

        // L1: shared decision cache
        if let Some(cached_source) = self.decision_cache.get(domain, group_id) {
            decision_l0_set(domain, group_id, cached_source);
            return match cached_source {
                Some(source) => FilterDecision::Block(source),
                None => FilterDecision::Allow,
            };
        }

        // Full block filter pipeline
        let guard = self.index.load();
        let block_source = guard.is_blocked(domain, group_id);

        self.decision_cache.set(domain, group_id, block_source);
        decision_l0_set(domain, group_id, block_source);

        match block_source {
            Some(source) => FilterDecision::Block(source),
            None => FilterDecision::Allow,
        }
    }

    async fn reload(&self) -> Result<(), DomainError> {
        info!("Block filter reload started");

        let new_index = compile_block_index(&self.pool, &self.http_client)
            .await
            .map_err(|e| {
                error!(error = %e, "Block filter reload failed");
                e
            })?;

        self.index.store(Arc::new(new_index));

        self.decision_cache.clear();
        decision_l0_clear();

        info!("Block filter reload completed");
        Ok(())
    }

    async fn load_client_groups(&self) -> Result<(), DomainError> {
        self.load_client_groups_inner().await
    }

    fn compiled_domain_count(&self) -> usize {
        self.index.load().total_blocked_domains
    }
}
