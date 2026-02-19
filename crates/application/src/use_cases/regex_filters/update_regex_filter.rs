use ferrous_dns_domain::{DomainAction, DomainError, RegexFilter};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository, RegexFilterRepository};

pub struct UpdateRegexFilterUseCase {
    repo: Arc<dyn RegexFilterRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateRegexFilterUseCase {
    pub fn new(
        repo: Arc<dyn RegexFilterRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            repo,
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &self,
        id: i64,
        name: Option<String>,
        pattern: Option<String>,
        action: Option<DomainAction>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<RegexFilter, DomainError> {
        self.repo.get_by_id(id).await?.ok_or_else(|| {
            DomainError::RegexFilterNotFound(format!("Regex filter {} not found", id))
        })?;

        if let Some(ref n) = name {
            RegexFilter::validate_name(n).map_err(DomainError::InvalidRegexFilter)?;
        }

        if let Some(ref p) = pattern {
            RegexFilter::validate_pattern(p).map_err(DomainError::InvalidRegexFilter)?;
        }

        if let Some(ref c) = comment {
            RegexFilter::validate_comment(&Some(Arc::from(c.as_str())))
                .map_err(DomainError::InvalidRegexFilter)?;
        }

        if let Some(gid) = group_id {
            self.group_repo
                .get_by_id(gid)
                .await?
                .ok_or_else(|| DomainError::GroupNotFound(format!("Group {} not found", gid)))?;
        }

        let updated = self
            .repo
            .update(id, name, pattern, action, group_id, comment, enabled)
            .await?;

        info!(
            filter_id = ?id,
            name = %updated.name,
            pattern = %updated.pattern,
            action = %updated.action.to_str(),
            enabled = %updated.enabled,
            "Regex filter updated successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after regex filter update");
        }

        Ok(updated)
    }
}
