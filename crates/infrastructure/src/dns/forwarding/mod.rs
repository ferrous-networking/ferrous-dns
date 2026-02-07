//! DNS Forwarding Layer
//!
//! Builds DNS query messages and parses upstream responses.
//! Uses `hickory-proto` for wire format serialization/deserialization,
//! but owns all query/response logic (no `hickory-resolver`).
//!
//! This module centralizes all DNS message construction and parsing,
//! eliminating the duplicated RecordType conversion and IP extraction
//! that was previously spread across resolver.rs, server.rs, and strategies.

pub mod message_builder;
pub mod record_type_map;
pub mod response_parser;

pub use message_builder::MessageBuilder;
pub use record_type_map::RecordTypeMapper;
pub use response_parser::{DnsResponse, ResponseParser};
