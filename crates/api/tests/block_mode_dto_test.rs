use ferrous_dns_api::dto::config::{block_mode_from_str, block_mode_to_string};
use ferrous_dns_domain::BlockResponseMode;

#[test]
fn block_mode_string_round_trips() {
    for mode in [
        BlockResponseMode::NullIp,
        BlockResponseMode::NxDomain,
        BlockResponseMode::NoData,
        BlockResponseMode::Refused,
    ] {
        assert_eq!(block_mode_from_str(&block_mode_to_string(mode)), mode);
    }
}

#[test]
fn unknown_block_mode_falls_back_to_null_ip() {
    assert_eq!(block_mode_from_str("bogus"), BlockResponseMode::NullIp);
    assert_eq!(block_mode_from_str(""), BlockResponseMode::NullIp);
}
