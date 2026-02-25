use super::QueryEvent;
use tokio::sync::mpsc;
use tracing::warn;

const QUERY_EVENT_CHANNEL_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct QueryEventEmitter {
    sender: Option<mpsc::Sender<QueryEvent>>,
}

impl QueryEventEmitter {
    pub fn new_disabled() -> Self {
        Self { sender: None }
    }

    pub fn new_enabled() -> (Self, mpsc::Receiver<QueryEvent>) {
        let (tx, rx) = mpsc::channel(QUERY_EVENT_CHANNEL_CAPACITY);
        let emitter = Self { sender: Some(tx) };
        (emitter, rx)
    }

    pub fn emit(&self, event: QueryEvent) {
        if let Some(ref tx) = self.sender {
            if tx.try_send(event).is_err() {
                warn!("query log channel full, dropping event");
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
