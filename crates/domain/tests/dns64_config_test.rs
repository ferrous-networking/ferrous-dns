use ferrous_dns_domain::Dns64Config;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[test]
fn default_is_disabled_with_well_known_prefix() {
    let cfg = Dns64Config::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.prefix, "64:ff9b::/96");
}

#[test]
fn toml_round_trips() {
    let cfg: Dns64Config = toml::from_str("enabled = true\nprefix = \"64:ff9b::/96\"").unwrap();
    assert!(cfg.enabled);
    assert_eq!(cfg.prefix, "64:ff9b::/96");

    let serialized = toml::Value::try_from(&cfg).unwrap();
    let table = serialized.as_table().unwrap();
    assert_eq!(table["enabled"].as_bool(), Some(true));
    assert_eq!(table["prefix"].as_str(), Some("64:ff9b::/96"));
}

#[test]
fn missing_prefix_falls_back_to_default() {
    let cfg: Dns64Config = toml::from_str("enabled = false").unwrap();
    assert_eq!(cfg.prefix, "64:ff9b::/96");
}

#[test]
fn parsed_prefix_accepts_slash_96_and_masks_host_bits() {
    let cfg = Dns64Config {
        enabled: true,
        prefix: "64:ff9b::/96".to_string(),
    };
    assert_eq!(
        cfg.parsed_prefix(),
        Some(Ipv6Addr::from_str("64:ff9b::").unwrap())
    );

    // A bare address (no length) is treated as /96.
    let bare = Dns64Config {
        enabled: true,
        prefix: "64:ff9b::".to_string(),
    };
    assert_eq!(
        bare.parsed_prefix(),
        Some(Ipv6Addr::from_str("64:ff9b::").unwrap())
    );

    // Host bits in the supplied prefix are zeroed.
    let dirty = Dns64Config {
        enabled: true,
        prefix: "64:ff9b::dead:beef/96".to_string(),
    };
    assert_eq!(
        dirty.parsed_prefix(),
        Some(Ipv6Addr::from_str("64:ff9b::").unwrap())
    );
}

#[test]
fn parsed_prefix_rejects_non_96_and_malformed() {
    for bad in [
        "64:ff9b::/64",
        "64:ff9b::/48",
        "64:ff9b::/128",
        "not-an-address/96",
        "192.168.0.0/96",
        "",
    ] {
        let cfg = Dns64Config {
            enabled: true,
            prefix: bad.to_string(),
        };
        assert!(
            cfg.parsed_prefix().is_none(),
            "expected None for prefix {bad:?}"
        );
    }
}
