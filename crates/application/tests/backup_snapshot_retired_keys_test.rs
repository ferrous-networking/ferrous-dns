//! Backups written by older releases carry config keys nothing read, and may
//! hold `throttle` as the tunneling action, which ran as `alert`. They must
//! keep importing.

use ferrous_dns_application::use_cases::backup::snapshot::SnapshotDnsConfig;
use ferrous_dns_domain::TunnelingAction;
use serde_json::json;

#[test]
fn test_older_dns_section_with_retired_keys_deserializes() {
    let dns: SnapshotDnsConfig = serde_json::from_value(json!({
        "upstream_servers": ["1.1.1.1:53"],
        "cache_enabled": true,
        "cache_eviction_strategy": "lru",
        "cache_max_entries": 1000,
        "cache_min_hit_rate": 0.0,
        "cache_min_frequency": 0,
        "cache_min_lfuk_score": 0.0,
        "cache_compaction_interval": 300,
        "cache_refresh_threshold": 0.8,
        "cache_optimistic_refresh": false,
        "cache_adaptive_thresholds": true,
        "cache_access_window_secs": 7200,
        "cache_min_ttl": 0,
        "cache_max_ttl": 86400,
        "block_non_fqdn": false,
        "block_private_ptr": false,
        "local_domain": null,
        "local_dns_server": null,
        "pools": [{
            "name": "p1",
            "strategy": "Balanced",
            "priority": 1,
            "servers": ["udp://9.9.9.9:53"],
            "weight": 5
        }],
        "malware": {
            "enabled": true,
            "rebinding_protection_enabled": true,
            "tunneling_detection": { "action": "throttle" },
            "dga_detection": {},
            "nxdomain_hijack": {},
            "response_ip_filter": {}
        }
    }))
    .expect("an older backup must deserialize");

    assert_eq!(dns.pools.unwrap()[0].servers, ["udp://9.9.9.9:53"]);
    assert_eq!(
        dns.malware.unwrap().tunneling_detection.action,
        TunnelingAction::Alert
    );
}
