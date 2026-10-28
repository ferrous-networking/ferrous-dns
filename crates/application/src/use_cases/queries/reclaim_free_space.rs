use crate::ports::FreeSpaceReclaimer;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct ReclaimFreeSpaceUseCase {
    reclaimer: Arc<dyn FreeSpaceReclaimer>,
}

impl ReclaimFreeSpaceUseCase {
    pub fn new(reclaimer: Arc<dyn FreeSpaceReclaimer>) -> Self {
        Self { reclaimer }
    }

    pub async fn execute(&self) -> Result<u64, DomainError> {
        self.reclaimer.reclaim_free_space().await
    }
}
