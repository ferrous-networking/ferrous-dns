use super::coarse_timer::coarse_now_ns;
use crate::drop_counter::DropCounter;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Bounds the client queries waiting on an upstream at once, over every
/// transport. Answers that need no upstream never take a slot, so they stay
/// serviceable while slow upstreams hold every one.
pub(super) struct UpstreamAdmission {
    slots: Semaphore,
    shed: Arc<DropCounter>,
}

impl UpstreamAdmission {
    pub(super) fn new(limit: usize, shed: Arc<DropCounter>) -> Self {
        Self {
            slots: Semaphore::new(limit),
            shed,
        }
    }

    /// A slot, held until the permit drops; `Err` sheds the query instead of
    /// queueing it behind the upstreams.
    pub(super) fn try_admit(&self) -> Result<SemaphorePermit<'_>, DomainError> {
        self.slots.try_acquire().map_err(|_| {
            // Distinguishes deliberate shedding from upstream failures for operators.
            if let Some(report) = self.shed.record(coarse_now_ns() / 1_000_000_000) {
                tracing::warn!(
                    shed = report.since_last,
                    total_shed = report.total,
                    "Upstream query capacity exhausted; queries shed"
                );
            }
            DomainError::UpstreamCapacityExhausted
        })
    }
}
