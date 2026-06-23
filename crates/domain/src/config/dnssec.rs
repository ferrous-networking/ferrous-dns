use serde::{Deserialize, Serialize};

/// DNSSEC validation enforcement mode (RFC 4035 / 6840).
///
/// Controls how the resolver treats DNSSEC validation results:
/// - `Off` — no validation; the DO bit is not set on upstream queries.
/// - `Permissive` — validate and tag every response, but never alter it
///   (no SERVFAIL on Bogus, no enforcement). This is the default.
/// - `Strict` — enforce: a Bogus validation returns SERVFAIL to the client
///   (unless the client set the CD bit).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
pub enum DnssecMode {
    Off,

    #[default]
    Permissive,

    Strict,
}

impl DnssecMode {
    /// Lowercase wire/API form ("off" / "permissive" / "strict").
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Permissive => "permissive",
            Self::Strict => "strict",
        }
    }

    /// Whether validation runs at all (DO bit set on upstream queries and the
    /// chain of trust validated). True for `Permissive` and `Strict`.
    pub fn validates(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Whether a Bogus validation must be enforced with SERVFAIL. Only `Strict`.
    pub fn enforces(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

impl std::fmt::Display for DnssecMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => f.write_str("Off"),
            Self::Permissive => f.write_str("Permissive"),
            Self::Strict => f.write_str("Strict"),
        }
    }
}

impl std::str::FromStr for DnssecMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "permissive" => Ok(Self::Permissive),
            "strict" => Ok(Self::Strict),
            other => Err(format!("Invalid DNSSEC mode: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn default_is_permissive() {
        assert_eq!(DnssecMode::default(), DnssecMode::Permissive);
    }

    #[test]
    fn validates_and_enforces() {
        assert!(!DnssecMode::Off.validates());
        assert!(DnssecMode::Permissive.validates());
        assert!(DnssecMode::Strict.validates());

        assert!(!DnssecMode::Off.enforces());
        assert!(!DnssecMode::Permissive.enforces());
        assert!(DnssecMode::Strict.enforces());
    }

    #[test]
    fn from_str_is_case_insensitive() {
        assert_eq!(DnssecMode::from_str("off").unwrap(), DnssecMode::Off);
        assert_eq!(
            DnssecMode::from_str("Permissive").unwrap(),
            DnssecMode::Permissive
        );
        assert_eq!(DnssecMode::from_str("STRICT").unwrap(), DnssecMode::Strict);
        assert!(DnssecMode::from_str("bogus").is_err());
    }

    #[test]
    fn deserializes_from_toml_pascalcase() {
        #[derive(Deserialize)]
        struct Wrap {
            mode: DnssecMode,
        }
        let w: Wrap = toml::from_str(r#"mode = "Strict""#).unwrap();
        assert_eq!(w.mode, DnssecMode::Strict);
    }
}
