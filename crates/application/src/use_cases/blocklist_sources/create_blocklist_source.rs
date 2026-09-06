use async_trait::async_trait;
use ferrous_dns_domain::{BlocklistSource, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{
    BlockFilterEnginePort, BlocklistSourceCreator, BlocklistSourceRepository, GroupRepository,
};

pub struct CreateBlocklistSourceUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl CreateBlocklistSourceUseCase {
    pub fn new(
        repo: Arc<dyn BlocklistSourceRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self {
            repo,
            group_repo,
            block_filter_engine: None,
        }
    }

    pub fn with_block_filter(mut self, engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        self.block_filter_engine = Some(engine);
        self
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        let source = self.persist(name, url, group_ids, comment, enabled).await?;

        if let Some(ref engine) = self.block_filter_engine {
            if let Err(e) = engine.reload().await {
                error!(error = %e, "Failed to reload block filter after blocklist source creation");
            }
        }

        Ok(source)
    }

    async fn persist(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        BlocklistSource::validate_name(&name).map_err(DomainError::InvalidBlocklistSource)?;

        BlocklistSource::validate_url(&url.as_deref().map(Arc::from))
            .map_err(DomainError::InvalidBlocklistSource)?;

        BlocklistSource::validate_comment(&comment.as_deref().map(Arc::from))
            .map_err(DomainError::InvalidBlocklistSource)?;

        for &gid in &group_ids {
            self.group_repo
                .get_by_id(gid)
                .await?
                .ok_or(DomainError::GroupNotFound(gid))?;
        }

        let source = self
            .repo
            .create(name.clone(), url, group_ids.clone(), comment, enabled)
            .await?;

        info!(
            source_id = ?source.id,
            name = %name,
            group_ids = ?group_ids,
            "Blocklist source created successfully"
        );

        Ok(source)
    }
}

#[async_trait]
impl BlocklistSourceCreator for CreateBlocklistSourceUseCase {
    async fn create_blocklist_source(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        // Backup import drives this in a loop, and a reload re-downloads every
        // list, so the batch caller reloads once instead of once per source.
        self.persist(name, url, group_ids, comment, enabled).await
    }
}
