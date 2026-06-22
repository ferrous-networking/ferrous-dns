//! Backward/forward compatibility of the backup [blocking] snapshot section:
//! pre-0.9 backups omit block_mode/block_ttl/sinkhole and must still import via
//! serde defaults; newer backups carry and restore the full block-response config.

use ferrous_dns_application::use_cases::backup::snapshot::SnapshotBlockingConfig;
use ferrous_dns_domain::BlockResponseMode;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn legacy_blocking_section_deserializes_with_defaults() {
    // A pre-0.9 backup only carried these three keys.
    let json = serde_json::json!({
        "enabled": true,
        "custom_blocked": [],
        "whitelist": []
    });
    let parsed: SnapshotBlockingConfig = serde_json::from_value(json).unwrap();
    assert_eq!(parsed.block_mode, BlockResponseMode::NullIp);
    assert_eq!(parsed.block_ttl, 60);
    assert_eq!(parsed.sinkhole_ipv4, None);
    assert_eq!(parsed.sinkhole_ipv6, None);
}

#[test]
fn full_blocking_section_round_trips() {
    let json = serde_json::json!({
        "enabled": true,
        "custom_blocked": [],
        "whitelist": [],
        "block_mode": "nxdomain",
        "block_ttl": 120,
        "sinkhole_ipv4": "192.168.1.2",
        "sinkhole_ipv6": "fd00::2"
    });
    let parsed: SnapshotBlockingConfig = serde_json::from_value(json).unwrap();
    assert_eq!(parsed.block_mode, BlockResponseMode::NxDomain);
    assert_eq!(parsed.block_ttl, 120);
    assert_eq!(parsed.sinkhole_ipv4, Some(Ipv4Addr::new(192, 168, 1, 2)));
    assert_eq!(
        parsed.sinkhole_ipv6,
        Some("fd00::2".parse::<Ipv6Addr>().unwrap())
    );

    // Re-serialize and confirm the custom targets survive a round-trip.
    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert_eq!(reserialized["sinkhole_ipv4"], "192.168.1.2");
    assert_eq!(reserialized["sinkhole_ipv6"], "fd00::2");
    assert_eq!(reserialized["block_mode"], "nxdomain");
}
