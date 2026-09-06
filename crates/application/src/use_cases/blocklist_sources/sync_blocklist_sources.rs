use ferrous_dns_domain::DomainError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::BlockFilterEnginePort;

pub struct SyncBlocklistSourcesUseCase {
    engine: Arc<dyn BlockFilterEnginePort>,
    running: Arc<AtomicBool>,
}

impl SyncBlocklistSourcesUseCase {
    pub fn new(engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        Self {
            engine,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts a block index rebuild in the background and returns immediately.
    ///
    /// Returns `Ok(false)` when a sync is already running: a rebuild re-downloads
    /// every source, so a second concurrent run would duplicate that work for no
    /// benefit.
    #[instrument(skip(self))]
    pub async fn execute(&self) -> Result<bool, DomainError> {
        if self.running.swap(true, Ordering::AcqRel) {
            info!("Blocklist sync already running; ignoring request");
            return Ok(false);
        }

        let engine = self.engine.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            info!("Manual blocklist sync started");
            match engine.reload().await {
                Ok(()) => info!("Manual blocklist sync completed"),
                Err(e) => error!(error = %e, "Manual blocklist sync failed"),
            }
            running.store(false, Ordering::Release);
        });

        Ok(true)
    }
}
