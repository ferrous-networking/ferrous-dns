//! Blocklist parser. Lists are imported by URL, so the text is remote input
//! even though it is not wire format.
#![no_main]

use ferrous_dns_infrastructure::dns::fuzz_api::{parse_list_text, ParsedEntry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    for entry in parse_list_text(text) {
        let domain = match &entry {
            ParsedEntry::Exact(d)
            | ParsedEntry::Wildcard(d)
            | ParsedEntry::Pattern(d)
            | ParsedEntry::DomainAndSubdomains(d) => d,
        };
        assert!(
            !domain.is_empty(),
            "blocklist parser emitted an empty rule, which would match everything"
        );
    }
});
