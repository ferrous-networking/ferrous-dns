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

/// See [`crate::dns::wire_response`]: whether re-sectioning a message may
/// rewrite the compressed names inside the RDATA of `rtype`.
pub fn rdata_has_names(rtype: u16) -> bool {
    crate::dns::wire_response::rdata_has_names(rtype)
}

/// See [`crate::dns::wire_response::cache_form`]: whether it declines a
/// message that re-sections, for names that read TTL bytes or do not walk.
pub fn cache_form_declines_names(upstream: &[u8]) -> bool {
    crate::dns::wire_response::cache_form_declines_names(upstream)
}
