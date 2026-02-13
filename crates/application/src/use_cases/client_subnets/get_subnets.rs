use ferrous_dns_domain::{ClientSubnet, DomainError};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::ClientSubnetRepository;

pub struct GetClientSubnetsUseCase {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
}

impl GetClientSubnetsUseCase {
    pub fn new(subnet_repo: Arc<dyn ClientSubnetRepository>) -> Self {
        Self { subnet_repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError> {
        self.subnet_repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<ClientSubnet>, DomainError> {
        self.subnet_repo.get_by_id(id).await
    }
}
