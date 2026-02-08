use ferrous_dns_domain::RecordType;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Event emitted for every DNS query that goes to an upstream server.
///
/// This event represents a single DNS query made by the resolver to an upstream
/// DNS server (e.g., 8.8.8.8, 1.1.1.1). These events are used for comprehensive
/// query logging, including DNSSEC validation queries (DS, DNSKEY, RRSIG).
///
/// ## Fields
///
/// - `domain`: The domain being queried (e.g., "google.com")
/// - `record_type`: The DNS record type (A, AAAA, DS, DNSKEY, etc.)
/// - `upstream_server`: The upstream server address (e.g., "8.8.8.8:53")
/// - `response_time_us`: Response time in microseconds
/// - `success`: Whether the query returned valid data
///
/// ## Size
///
/// This struct is designed to be small (~48 bytes) for efficient channel transmission:
/// - `domain`: 16 bytes (Arc<str>)
/// - `record_type`: 4 bytes (enum)
/// - `upstream_server`: 24 bytes (String)
/// - `response_time_us`: 8 bytes (u64)
/// - `success`: 1 byte (bool)
///
/// ## Clone Cost
///
/// Cloning is cheap due to Arc<str> - only increments reference count.
#[derive(Debug, Clone)]
pub struct QueryEvent {
    /// Domain being queried (Arc for cheap cloning)
    pub domain: Arc<str>,

    /// DNS record type (A, AAAA, DS, DNSKEY, RRSIG, etc.)
    pub record_type: RecordType,

    /// Upstream server that handled the query (e.g., "8.8.8.8:53")
    pub upstream_server: String,

    /// Query response time in microseconds
    pub response_time_us: u64,

    /// Whether the query returned valid data (true) or failed (false)
    pub success: bool,
}

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
///
/// ## Usage Patterns
///
/// ```rust,no_run
/// use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
///
/// // Disabled emitter (zero overhead)
/// let emitter = QueryEventEmitter::new_disabled();
/// assert!(!emitter.is_enabled());
///
/// // Enabled emitter
/// let (emitter, rx) = QueryEventEmitter::new_enabled();
/// assert!(emitter.is_enabled());
///
/// // Clone for multiple threads
/// let emitter_clone = emitter.clone();
/// tokio::spawn(async move {
///     // Use emitter_clone in another task
/// });
/// ```
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
    ///
    /// ## Example
    ///
    /// ```rust
    /// use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
    ///
    /// let emitter = QueryEventEmitter::new_disabled();
    /// assert!(!emitter.is_enabled());
    ///
    /// // emit() is a no-op
    /// // emitter.emit(event); // Does nothing
    /// ```
    pub fn new_disabled() -> Self {
        Self { sender: None }
    }

    /// Creates an enabled emitter and returns the receiver.
    ///
    /// Returns a tuple of:
    /// - `QueryEventEmitter`: The emitter to be used in hot paths
    /// - `UnboundedReceiver<QueryEvent>`: The receiver for the consumer task
    ///
    /// ## Example
    ///
    /// ```rust
    /// use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
    ///
    /// let (emitter, mut rx) = QueryEventEmitter::new_enabled();
    /// assert!(emitter.is_enabled());
    ///
    /// // Spawn consumer task
    /// tokio::spawn(async move {
    ///     while let Some(event) = rx.recv().await {
    ///         println!("Query: {} {:?}", event.domain, event.record_type);
    ///     }
    /// });
    /// ```
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
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use ferrous_dns_infrastructure::dns::events::{QueryEvent, QueryEventEmitter};
    /// use ferrous_dns_domain::RecordType;
    /// use std::sync::Arc;
    ///
    /// let (emitter, _rx) = QueryEventEmitter::new_enabled();
    ///
    /// // Emit event (100-200ns, non-blocking)
    /// emitter.emit(QueryEvent {
    ///     domain: Arc::from("example.com"),
    ///     record_type: RecordType::A,
    ///     upstream_server: "8.8.8.8:53".to_string(),
    ///     response_time_us: 1000,
    ///     success: true,
    /// });
    ///
    /// // Continues immediately! No waiting!
    /// ```
    pub fn emit(&self, event: QueryEvent) {
        if let Some(ref tx) = self.sender {
            // Ignore send errors - logging is best-effort.
            // If the receiver is dropped or the channel is full (shouldn't happen
            // with unbounded), we silently drop the event rather than panicking
            // or blocking the hot path.
            let _ = tx.send(event);
        }
        // If sender is None (disabled), this is a no-op
    }

    /// Returns true if the emitter is enabled.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
    ///
    /// let disabled = QueryEventEmitter::new_disabled();
    /// assert!(!disabled.is_enabled());
    ///
    /// let (enabled, _rx) = QueryEventEmitter::new_enabled();
    /// assert!(enabled.is_enabled());
    /// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_disabled_emitter() {
        let emitter = QueryEventEmitter::new_disabled();

        assert!(!emitter.is_enabled());
        assert_eq!(
            format!("{:?}", emitter),
            "QueryEventEmitter { enabled: false }"
        );

        // emit() should be a no-op
        let event = QueryEvent {
            domain: Arc::from("test.com"),
            record_type: RecordType::A,
            upstream_server: "8.8.8.8:53".to_string(),
            response_time_us: 1000,
            success: true,
        };

        emitter.emit(event); // Should not panic
    }

    #[test]
    fn test_enabled_emitter() {
        let (emitter, _rx) = QueryEventEmitter::new_enabled();

        assert!(emitter.is_enabled());
        assert_eq!(
            format!("{:?}", emitter),
            "QueryEventEmitter { enabled: true }"
        );
    }

    #[tokio::test]
    async fn test_emit_and_receive() {
        let (emitter, mut rx) = QueryEventEmitter::new_enabled();

        // Emit event
        let event = QueryEvent {
            domain: Arc::from("example.com"),
            record_type: RecordType::A,
            upstream_server: "8.8.8.8:53".to_string(),
            response_time_us: 1234,
            success: true,
        };

        emitter.emit(event.clone());

        // Receive event
        let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Channel closed");

        assert_eq!(received.domain.as_ref(), "example.com");
        assert_eq!(received.record_type, RecordType::A);
        assert_eq!(received.upstream_server, "8.8.8.8:53");
        assert_eq!(received.response_time_us, 1234);
        assert!(received.success);
    }

    #[tokio::test]
    async fn test_multiple_events() {
        let (emitter, mut rx) = QueryEventEmitter::new_enabled();

        // Emit multiple events
        for i in 0..10 {
            emitter.emit(QueryEvent {
                domain: Arc::from(format!("test{}.com", i)),
                record_type: RecordType::A,
                upstream_server: "8.8.8.8:53".to_string(),
                response_time_us: i as u64 * 100,
                success: i % 2 == 0,
            });
        }

        // Receive all events
        let mut count = 0;
        while let Ok(Some(_event)) =
            tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
        {
            count += 1;
            if count == 10 {
                break;
            }
        }

        assert_eq!(count, 10);
    }

    #[test]
    fn test_clone_emitter() {
        let (emitter1, _rx) = QueryEventEmitter::new_enabled();
        let emitter2 = emitter1.clone();

        assert!(emitter1.is_enabled());
        assert!(emitter2.is_enabled());

        // Both should work independently
        let event = QueryEvent {
            domain: Arc::from("test.com"),
            record_type: RecordType::A,
            upstream_server: "8.8.8.8:53".to_string(),
            response_time_us: 1000,
            success: true,
        };

        emitter1.emit(event.clone());
        emitter2.emit(event);
    }

    #[tokio::test]
    async fn test_receiver_dropped() {
        let (emitter, rx) = QueryEventEmitter::new_enabled();

        // Drop receiver
        drop(rx);

        // Emit should not panic even though receiver is dropped
        let event = QueryEvent {
            domain: Arc::from("test.com"),
            record_type: RecordType::A,
            upstream_server: "8.8.8.8:53".to_string(),
            response_time_us: 1000,
            success: true,
        };

        emitter.emit(event); // Should not panic
    }

    #[test]
    fn test_default_is_disabled() {
        let emitter = QueryEventEmitter::default();
        assert!(!emitter.is_enabled());
    }

    #[test]
    fn test_query_event_clone() {
        let event1 = QueryEvent {
            domain: Arc::from("test.com"),
            record_type: RecordType::AAAA,
            upstream_server: "1.1.1.1:53".to_string(),
            response_time_us: 5000,
            success: false,
        };

        let event2 = event1.clone();

        assert_eq!(event1.domain, event2.domain);
        assert_eq!(event1.record_type, event2.record_type);
        assert_eq!(event1.upstream_server, event2.upstream_server);
        assert_eq!(event1.response_time_us, event2.response_time_us);
        assert_eq!(event1.success, event2.success);

        // Arc should be cheaply cloned (reference counting)
        assert!(Arc::ptr_eq(&event1.domain, &event2.domain));
    }

    #[test]
    fn test_dnssec_event_types() {
        let ds_event = QueryEvent {
            domain: Arc::from("example.com"),
            record_type: RecordType::DS,
            upstream_server: "8.8.8.8:53".to_string(),
            response_time_us: 1000,
            success: true,
        };

        let dnskey_event = QueryEvent {
            domain: Arc::from("example.com"),
            record_type: RecordType::DNSKEY,
            upstream_server: "8.8.8.8:53".to_string(),
            response_time_us: 1500,
            success: true,
        };

        assert_eq!(ds_event.record_type, RecordType::DS);
        assert_eq!(dnskey_event.record_type, RecordType::DNSKEY);
    }

    #[tokio::test]
    async fn test_concurrent_emits() {
        let (emitter, mut rx) = QueryEventEmitter::new_enabled();

        // Spawn multiple tasks emitting concurrently
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let emitter = emitter.clone();
                tokio::spawn(async move {
                    for j in 0..10 {
                        emitter.emit(QueryEvent {
                            domain: Arc::from(format!("task{}-query{}.com", i, j)),
                            record_type: RecordType::A,
                            upstream_server: "8.8.8.8:53".to_string(),
                            response_time_us: (i * 10 + j) as u64,
                            success: true,
                        });
                    }
                })
            })
            .collect();

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Receive all events (10 tasks × 10 events = 100)
        let mut count = 0;
        while let Ok(Some(_event)) =
            tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
        {
            count += 1;
            if count == 100 {
                break;
            }
        }

        assert_eq!(count, 100);
    }
}
