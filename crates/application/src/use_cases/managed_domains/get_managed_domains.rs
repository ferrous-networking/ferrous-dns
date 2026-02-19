use ferrous_dns_domain::{DomainError, ManagedDomain};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::ManagedDomainRepository;

pub struct GetManagedDomainsUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
}

impl GetManagedDomainsUseCase {
    pub fn new(repo: Arc<dyn ManagedDomainRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<ManagedDomain>, DomainError> {
        self.repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<ManagedDomain>, DomainError> {
        self.repo.get_by_id(id).await
    }
}
