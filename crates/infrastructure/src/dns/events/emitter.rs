use super::QueryEvent;
use crate::dns::cache::coarse_clock::coarse_now_secs;
use crate::drop_counter::DropCounter;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

const QUERY_EVENT_CHANNEL_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct QueryEventEmitter {
    sender: Option<(mpsc::Sender<QueryEvent>, Arc<DropCounter>)>,
}

impl QueryEventEmitter {
    pub fn new_disabled() -> Self {
        Self { sender: None }
    }

    pub fn new_enabled() -> (Self, mpsc::Receiver<QueryEvent>) {
        let (tx, rx) = mpsc::channel(QUERY_EVENT_CHANNEL_CAPACITY);
        let emitter = Self {
            sender: Some((tx, Arc::default())),
        };
        (emitter, rx)
    }

    pub fn emit(&self, event: QueryEvent) {
        if let Some((tx, dropped)) = &self.sender {
            if tx.try_send(event).is_err() {
                if let Some(report) = dropped.record(coarse_now_secs()) {
                    warn!(
                        dropped = report.since_last,
                        total_dropped = report.total,
                        "Query event channel unavailable; events dropped"
                    );
                }
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.sender.is_some()
    }
}

impl Default for QueryEventEmitter {
    fn default() -> Self {
        Self::new_disabled()
    }
}

impl std::fmt::Debug for QueryEventEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryEventEmitter")
            .field("enabled", &self.is_enabled())
            .finish()
    }
}
