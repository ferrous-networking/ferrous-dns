use async_trait::async_trait;
use ferrous_dns_domain::{BlocklistSource, DomainError};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{BlocklistSourceCreator, BlocklistSourceRepository, GroupRepository};

pub struct CreateBlocklistSourceUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateBlocklistSourceUseCase {
    pub fn new(
        repo: Arc<dyn BlocklistSourceRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self { repo, group_repo }
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
        self.execute(name, url, group_ids, comment, enabled).await
    }
}
