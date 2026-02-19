use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository, ManagedDomainRepository};

pub struct CreateManagedDomainUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl CreateManagedDomainUseCase {
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
    pub async fn execute(
        &self,
        name: String,
        domain: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<ManagedDomain, DomainError> {
        ManagedDomain::validate_name(&name).map_err(DomainError::InvalidManagedDomain)?;
        ManagedDomain::validate_domain(&domain).map_err(DomainError::InvalidManagedDomain)?;
        ManagedDomain::validate_comment(&comment.as_deref().map(Arc::from))
            .map_err(DomainError::InvalidManagedDomain)?;

        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or_else(|| DomainError::GroupNotFound(format!("Group {} not found", group_id)))?;

        let managed_domain = self
            .repo
            .create(
                name.clone(),
                domain.clone(),
                action,
                group_id,
                comment,
                enabled,
            )
            .await?;

        info!(
            domain_id = ?managed_domain.id,
            name = %name,
            domain = %domain,
            action = %action.to_str(),
            group_id = group_id,
            "Managed domain created successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after managed domain creation");
        }

        Ok(managed_domain)
    }
}
