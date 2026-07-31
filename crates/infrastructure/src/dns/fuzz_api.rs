//! Facade over parsers that are crate-private in a normal build, so the
//! `fuzz/` crate can reach them without widening the public API.
//!
//! Only compiled with the non-default `fuzzing` feature. Everything here is a
//! thin wrapper — no logic lives in this module, so a fuzz finding always maps
//! back to production code.

use bytes::Bytes;

pub use crate::dns::block_filter::compiler::ParsedEntry;

/// See [`crate::dns::forwarding::response_validator`]: undoes the 0x20
/// randomization by lowercasing every literal owner name in a response.
pub fn lowercase_owner_names(wire: &Bytes) -> Option<Bytes> {
    crate::dns::forwarding::response_validator::lowercase_owner_names(wire)
}

/// See [`crate::dns::block_filter`]: parses a downloaded blocklist (hosts,
/// Adblock Plus or plain-domain syntax) into rules.
pub fn parse_list_text(text: &str) -> Vec<ParsedEntry> {
    crate::dns::block_filter::compiler::parse_list_text(text)
}
