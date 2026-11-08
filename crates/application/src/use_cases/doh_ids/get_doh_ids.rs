use crate::ports::DohIdRepository;
use ferrous_dns_domain::{DohId, DomainError};
use std::sync::Arc;
use tracing::instrument;

pub struct GetDohIdsUseCase {
    doh_id_repo: Arc<dyn DohIdRepository>,
}

impl GetDohIdsUseCase {
    pub fn new(doh_id_repo: Arc<dyn DohIdRepository>) -> Self {
        Self { doh_id_repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<DohId>, DomainError> {
        self.doh_id_repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<DohId>, DomainError> {
        self.doh_id_repo.get_by_id(id).await
    }
}
