use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository, ManagedDomainRepository};

pub struct UpdateManagedDomainUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateManagedDomainUseCase {
    pub fn new(
        repo: Arc<dyn ManagedDomainRepository>,
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
        domain: Option<String>,
        action: Option<DomainAction>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<ManagedDomain, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ManagedDomainNotFound(id))?;

        if let Some(ref n) = name {
            ManagedDomain::validate_name(n).map_err(DomainError::InvalidManagedDomain)?;
        }

        if let Some(ref d) = domain {
            ManagedDomain::validate_domain(d).map_err(DomainError::InvalidManagedDomain)?;
        }

        if let Some(ref c) = comment {
            ManagedDomain::validate_comment(&Some(Arc::from(c.as_str())))
                .map_err(DomainError::InvalidManagedDomain)?;
        }

        if let Some(gid) = group_id {
            self.group_repo
                .get_by_id(gid)
                .await?
                .ok_or(DomainError::GroupNotFound(gid))?;
        }

        let updated = self
            .repo
            .update(id, name, domain, action, group_id, comment, enabled)
            .await?;

        info!(
            domain_id = ?id,
            name = %updated.name,
            domain = %updated.domain,
            action = %updated.action.to_str(),
            enabled = %updated.enabled,
            "Managed domain updated successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after managed domain update");
        }

        Ok(updated)
    }
}
