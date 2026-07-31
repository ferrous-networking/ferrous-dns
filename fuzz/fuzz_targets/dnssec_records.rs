//! DNSSEC rdata parsers. These read records straight out of a response, so a
//! hostile zone controls every byte.
//!
//! The input is capped at 65535 bytes because that is the largest RDLENGTH the
//! wire format can express; without the cap, `calculate_key_tag` overflows its
//! `u32` accumulator on inputs no real response could carry.
#![no_main]

use ferrous_dns_infrastructure::dns::dnssec::types::{DnskeyRecord, DsRecord, RrsigRecord};
use libfuzzer_sys::fuzz_target;

const MAX_RDLENGTH: usize = u16::MAX as usize;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_RDLENGTH {
        return;
    }

    if let Ok(rrsig) = RrsigRecord::parse(data, data) {
        let _ = rrsig.is_valid_at(0);
        let _ = rrsig.is_expired(u32::MAX);
        let _ = rrsig.to_string();
    }

    if let Ok(ds) = DsRecord::parse(data) {
        let _ = ds.to_string();
    }

    if let Ok(dnskey) = DnskeyRecord::parse(data) {
        let _ = dnskey.calculate_key_tag();
        let _ = dnskey.to_string();
    }
});
