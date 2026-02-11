//! DNS query event system
//!
//! This module provides a non-blocking event system for tracking DNS queries.
//!
//! ## Components
//!
//! - `QueryEvent`: Event struct representing a single DNS query
//! - `QueryEventEmitter`: Non-blocking emitter for fire-and-forget events
//! - `QueryMetrics`: Thread-safe metrics tracker for query events
//!
//! ## Performance
//!
//! - Emitter disabled: 0ns overhead (no-op)
//! - Emitter enabled: ~100-200ns per emit
//! - Never blocks the hot path
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ferrous_dns_infrastructure::dns::events::{QueryEventEmitter, QueryMetrics};
//!
//! // Create emitter and metrics
//! let (emitter, mut rx) = QueryEventEmitter::new_enabled();
//! let metrics = QueryMetrics::new();
//!
//! // Spawn consumer task
//! tokio::spawn(async move {
//!     while let Some(event) = rx.recv().await {
//!         metrics.track(&event);
//!     }
//! });
//!
//! // Use emitter in hot path (non-blocking!)
//! // emitter.emit(event);
//! ```

pub mod emitter;
pub mod metrics;
pub mod types;

pub use emitter::QueryEventEmitter;
pub use metrics::QueryMetrics;
pub use types::QueryEvent;
