use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// How a blocked (or security-flagged) domain is answered on the wire.
///
/// The default, `NullIp`, returns a cacheable `NOERROR` answer pointing at the
/// null address (`0.0.0.0` / `::`) so clients stop re-querying. `Refused` is the
/// legacy behaviour and is non-cacheable (RFC 2308 §7), which causes clients to
/// retry aggressively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseMode {
    /// `NOERROR` + `0.0.0.0` (A) / `::` (AAAA); NODATA for other record types.
    #[default]
    NullIp,
    /// `NXDOMAIN`.
    #[serde(rename = "nxdomain")]
    NxDomain,
    /// `NOERROR` with an empty answer section.
    #[serde(rename = "nodata")]
    NoData,
    /// `REFUSED` (legacy, non-cacheable).
    Refused,
}

impl BlockResponseMode {
    /// The snake_case wire/config string for this mode (matches the serde rename).
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockResponseMode::NullIp => "null_ip",
            BlockResponseMode::NxDomain => "nxdomain",
            BlockResponseMode::NoData => "nodata",
            BlockResponseMode::Refused => "refused",
        }
    }
}

/// Default TTL (seconds) for blocked answers; shared as the single source of
/// truth for the config default and the API DTO default.
pub const DEFAULT_BLOCK_TTL: u32 = 60;

fn default_block_ttl() -> u32 {
    DEFAULT_BLOCK_TTL
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockingConfig {
    pub enabled: bool,

    #[serde(default)]
    pub custom_blocked: Vec<String>,

    #[serde(default)]
    pub whitelist: Vec<String>,

    #[serde(default)]
    pub block_mode: BlockResponseMode,

    #[serde(default = "default_block_ttl")]
    pub block_ttl: u32,

    /// Optional custom A target for `null_ip` blocked answers. When unset, the
    /// null address `0.0.0.0` is used. Lets operators point blocked domains at a
    /// local block-page server instead of a dead address.
    #[serde(default)]
    pub sinkhole_ipv4: Option<Ipv4Addr>,

    /// Optional custom AAAA target for `null_ip` blocked answers. When unset, the
    /// null address `::` is used.
    #[serde(default)]
    pub sinkhole_ipv6: Option<Ipv6Addr>,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_blocked: vec![],
            whitelist: vec![],
            block_mode: BlockResponseMode::default(),
            block_ttl: default_block_ttl(),
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_mode_serializes_to_snake_case() {
        for (mode, expected) in [
            (BlockResponseMode::NullIp, "null_ip"),
            (BlockResponseMode::NxDomain, "nxdomain"),
            (BlockResponseMode::NoData, "nodata"),
            (BlockResponseMode::Refused, "refused"),
        ] {
            let value = toml::Value::try_from(mode).unwrap();
            assert_eq!(value.as_str(), Some(expected));
        }
    }

    #[test]
    fn block_mode_deserializes_from_snake_case() {
        for (text, expected) in [
            ("null_ip", BlockResponseMode::NullIp),
            ("nxdomain", BlockResponseMode::NxDomain),
            ("nodata", BlockResponseMode::NoData),
            ("refused", BlockResponseMode::Refused),
        ] {
            let config: BlockingConfig =
                toml::from_str(&format!("enabled = true\nblock_mode = \"{text}\"")).unwrap();
            assert_eq!(config.block_mode, expected);
        }
    }

    #[test]
    fn unknown_block_mode_errors() {
        assert!(
            toml::from_str::<BlockingConfig>("enabled = true\nblock_mode = \"bogus\"").is_err()
        );
    }

    #[test]
    fn defaults_are_null_ip_and_ttl_60() {
        let config = BlockingConfig::default();
        assert_eq!(config.block_mode, BlockResponseMode::NullIp);
        assert_eq!(config.block_ttl, 60);
    }

    #[test]
    fn missing_block_fields_fall_back_to_defaults() {
        let config: BlockingConfig = toml::from_str("enabled = true").unwrap();
        assert_eq!(config.block_mode, BlockResponseMode::NullIp);
        assert_eq!(config.block_ttl, 60);
    }

    #[test]
    fn custom_block_ttl_is_honoured() {
        let config: BlockingConfig = toml::from_str("enabled = true\nblock_ttl = 300").unwrap();
        assert_eq!(config.block_ttl, 300);
    }

    #[test]
    fn sinkhole_addresses_default_to_none() {
        let config: BlockingConfig = toml::from_str("enabled = true").unwrap();
        assert_eq!(config.sinkhole_ipv4, None);
        assert_eq!(config.sinkhole_ipv6, None);
    }

    #[test]
    fn sinkhole_addresses_round_trip() {
        let config: BlockingConfig = toml::from_str(
            "enabled = true\nsinkhole_ipv4 = \"192.168.1.2\"\nsinkhole_ipv6 = \"fd00::2\"",
        )
        .unwrap();
        assert_eq!(config.sinkhole_ipv4, Some(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(
            config.sinkhole_ipv6,
            Some("fd00::2".parse::<Ipv6Addr>().unwrap())
        );

        let serialized = toml::Value::try_from(&config).unwrap();
        let blocking = serialized.as_table().unwrap();
        assert_eq!(blocking["sinkhole_ipv4"].as_str(), Some("192.168.1.2"));
        assert_eq!(blocking["sinkhole_ipv6"].as_str(), Some("fd00::2"));
    }

    #[test]
    fn invalid_sinkhole_address_errors() {
        assert!(
            toml::from_str::<BlockingConfig>("enabled = true\nsinkhole_ipv4 = \"10.0.0.300\"")
                .is_err()
        );
    }
}
