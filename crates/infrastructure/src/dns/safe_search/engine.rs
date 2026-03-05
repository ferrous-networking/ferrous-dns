use super::domains::{cname_target, domains_for};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use ferrous_dns_application::ports::{SafeSearchConfigRepository, SafeSearchEnginePort};
use ferrous_dns_domain::{DomainError, SafeSearchConfig, SafeSearchEngine as Engine, YouTubeMode};
use rustc_hash::FxHashMap;
use std::sync::Arc;
use tracing::{error, info};

/// Compiled, read-optimised Safe Search lookup table.
struct SafeSearchIndex {
    /// Maps each monitored search engine domain to its engine type.
    domain_to_engine: FxHashMap<Box<str>, Engine>,
    /// Maps (group_id, engine) → (enabled, youtube_strict).
    group_configs: FxHashMap<(i64, Engine), (bool, bool)>,
}

impl SafeSearchIndex {
    fn empty() -> Self {
        Self {
            domain_to_engine: FxHashMap::default(),
            group_configs: FxHashMap::default(),
        }
    }

    /// Compiles an index from persisted configurations.
    fn from_configs(configs: &[SafeSearchConfig]) -> Self {
        let mut domain_to_engine: FxHashMap<Box<str>, Engine> = FxHashMap::default();
        let mut group_configs: FxHashMap<(i64, Engine), (bool, bool)> = FxHashMap::default();

        for engine in Engine::all() {
            for domain in domains_for(*engine) {
                domain_to_engine.insert(Box::from(*domain), *engine);
            }
        }

        for cfg in configs {
            let youtube_strict = matches!(cfg.youtube_mode, YouTubeMode::Strict);
            group_configs.insert((cfg.group_id, cfg.engine), (cfg.enabled, youtube_strict));
        }

        Self {
            domain_to_engine,
            group_configs,
        }
    }

    #[inline]
    fn cname_for(&self, domain: &str, group_id: i64) -> Option<&'static str> {
        let normalised = domain.trim_end_matches('.');
        let lower;
        let lookup = if normalised.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = normalised.to_ascii_lowercase();
            lower.as_str()
        } else {
            normalised
        };

        let engine = self.domain_to_engine.get(lookup)?;
        let &(enabled, youtube_strict) = self.group_configs.get(&(group_id, *engine))?;

        if !enabled {
            return None;
        }

        Some(cname_target(*engine, youtube_strict))
    }
}

/// Safe Search enforcement engine backed by an `ArcSwap<SafeSearchIndex>`.
///
/// The index is swapped atomically when configuration changes, with no
/// lock contention on the DNS query hot path.
pub struct SafeSearchEnforcer {
    index: ArcSwap<SafeSearchIndex>,
    config_repo: Arc<dyn SafeSearchConfigRepository>,
}

impl SafeSearchEnforcer {
    /// Initialises the engine by loading all configurations from the repository.
    pub async fn new(
        config_repo: Arc<dyn SafeSearchConfigRepository>,
    ) -> Result<Arc<Self>, DomainError> {
        let engine = Arc::new(Self {
            index: ArcSwap::from_pointee(SafeSearchIndex::empty()),
            config_repo,
        });

        engine.reload_inner().await?;
        info!("SafeSearchEnforcer initialised");
        Ok(engine)
    }

    async fn reload_inner(&self) -> Result<(), DomainError> {
        let configs = self.config_repo.get_all().await?;
        let new_index = SafeSearchIndex::from_configs(&configs);
        self.index.store(Arc::new(new_index));
        Ok(())
    }
}

#[async_trait]
impl SafeSearchEnginePort for SafeSearchEnforcer {
    #[inline]
    fn cname_for(&self, domain: &str, group_id: i64) -> Option<&'static str> {
        self.index.load().cname_for(domain, group_id)
    }

    async fn reload(&self) -> Result<(), DomainError> {
        if let Err(e) = self.reload_inner().await {
            error!(error = %e, "Failed to reload Safe Search index");
            return Err(e);
        }
        info!("Safe Search index reloaded");
        Ok(())
    }
}
