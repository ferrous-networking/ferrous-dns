use crate::ports::BlockFilterEnginePort;
use std::sync::Arc;

pub struct GetBlockFilterStatsUseCase {
    engine: Arc<dyn BlockFilterEnginePort>,
}

impl GetBlockFilterStatsUseCase {
    pub fn new(engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        Self { engine }
    }

    pub fn execute(&self) -> usize {
        self.engine.compiled_domain_count()
    }
}
