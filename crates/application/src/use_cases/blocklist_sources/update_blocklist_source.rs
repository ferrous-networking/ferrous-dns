use ferrous_dns_domain::{BlocklistSource, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, BlocklistSourceRepository, GroupRepository};

pub struct UpdateBlocklistSourceUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl UpdateBlocklistSourceUseCase {
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
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_ids: Option<Vec<i64>>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<BlocklistSource, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::BlocklistSourceNotFound(id))?;

        if let Some(ref n) = name {
            BlocklistSource::validate_name(n).map_err(DomainError::InvalidBlocklistSource)?;
        }

        if let Some(ref u_opt) = url {
            BlocklistSource::validate_url(&u_opt.as_deref().map(Arc::from))
                .map_err(DomainError::InvalidBlocklistSource)?;
        }

        if let Some(ref c) = comment {
            BlocklistSource::validate_comment(&Some(Arc::from(c.as_str())))
                .map_err(DomainError::InvalidBlocklistSource)?;
        }

        if let Some(ref ids) = group_ids {
            for &gid in ids {
                self.group_repo
                    .get_by_id(gid)
                    .await?
                    .ok_or(DomainError::GroupNotFound(gid))?;
            }
        }

        let updated = self
            .repo
            .update(id, name, url, group_ids, comment, enabled)
            .await?;

        info!(
            source_id = ?id,
            name = %updated.name,
            enabled = %updated.enabled,
            "Blocklist source updated successfully"
        );

        if let Some(ref engine) = self.block_filter_engine {
            if let Err(e) = engine.reload().await {
                error!(error = %e, "Failed to reload block filter after blocklist source update");
            }
        }

        Ok(updated)
    }
}
