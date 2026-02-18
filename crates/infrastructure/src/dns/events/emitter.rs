use super::QueryEvent;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct QueryEventEmitter {
    sender: Option<mpsc::UnboundedSender<QueryEvent>>,
}

impl QueryEventEmitter {
    pub fn new_disabled() -> Self {
        Self { sender: None }
    }

    pub fn new_enabled() -> (Self, mpsc::UnboundedReceiver<QueryEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let emitter = Self { sender: Some(tx) };
        (emitter, rx)
    }

    pub fn emit(&self, event: QueryEvent) {
        if let Some(ref tx) = self.sender {
            let _ = tx.send(event);
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
