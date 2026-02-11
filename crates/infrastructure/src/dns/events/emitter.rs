use super::QueryEvent;
use tokio::sync::mpsc;

/// Non-blocking event emitter for DNS query events.
///
/// This emitter uses an unbounded channel to send events without ever blocking
/// the hot path (query_server). Events are fire-and-forget - if the channel
/// is full or closed, events are silently dropped (logging is best-effort).
///
/// ## Performance Characteristics
///
/// - **Enabled**: ~100-200ns per emit (channel send)
/// - **Disabled**: 0ns per emit (no-op when sender = None)
/// - **Never blocks**: Uses `UnboundedSender::send()` which never awaits
///
/// ## Thread Safety
///
/// This struct is `Clone` and can be shared across threads safely. The underlying
/// `UnboundedSender` is wrapped in Arc internally by tokio.
#[derive(Clone)]
pub struct QueryEventEmitter {
    /// Optional sender for events.
    /// - Some: Emitter is enabled, events are sent
    /// - None: Emitter is disabled, emit() is a no-op
    sender: Option<mpsc::UnboundedSender<QueryEvent>>,
}

impl QueryEventEmitter {
    /// Creates a disabled emitter (zero overhead).
    ///
    /// When disabled, `emit()` is a no-op and has zero performance overhead.
    /// This is useful for production environments where query logging is disabled.
    pub fn new_disabled() -> Self {
        Self { sender: None }
    }

    /// Creates an enabled emitter and returns the receiver.
    ///
    /// Returns a tuple of:
    /// - `QueryEventEmitter`: The emitter to be used in hot paths
    /// - `UnboundedReceiver<QueryEvent>`: The receiver for the consumer task
    pub fn new_enabled() -> (Self, mpsc::UnboundedReceiver<QueryEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let emitter = Self { sender: Some(tx) };
        (emitter, rx)
    }

    /// Emits a query event (non-blocking, fire-and-forget).
    ///
    /// This method never blocks and returns immediately. If the emitter is disabled
    /// or the channel is closed, the event is silently dropped (logging is best-effort).
    ///
    /// ## Performance
    ///
    /// - **Disabled**: 0ns (no-op)
    /// - **Enabled**: ~100-200ns (channel send)
    /// - **Never awaits**: Always synchronous
    pub fn emit(&self, event: QueryEvent) {
        if let Some(ref tx) = self.sender {
            let _ = tx.send(event);
        }
    }

    /// Returns true if the emitter is enabled.
    pub fn is_enabled(&self) -> bool {
        self.sender.is_some()
    }
}

impl Default for QueryEventEmitter {
    /// Default is a disabled emitter (zero overhead).
    ///
    /// This ensures that if an emitter is accidentally left uninitialized,
    /// it defaults to the safe, zero-overhead disabled state.
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
