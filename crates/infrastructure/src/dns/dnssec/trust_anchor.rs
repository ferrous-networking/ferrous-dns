use super::crypto::SignatureVerifier;
use super::types::{DnskeyRecord, DsRecord};
use base64::{engine::general_purpose::STANDARD, Engine};
use data_encoding::HEXLOWER_PERMISSIVE;
use ferrous_dns_domain::DomainError;
use std::path::Path;
use std::str::FromStr;

/// DNSKEY REVOKE bit (RFC 5011 §2.1). A revoked key hashes to a different key
/// tag, so it can never match an anchor — flagging it as "unanchored" would be
/// pure noise.
const REVOKE_FLAG: u16 = 0x0080;

/// What a trust anchor pins: the full DNSKEY, or the DS digest of it.
///
/// IANA publishes the root anchors as DS records
/// (<https://data.iana.org/root-anchors/root-anchors.xml>), so that is the form
/// the embedded set uses. An operator-supplied file may carry either, since
/// both appear in the wild: `unbound-anchor -a` writes DNSKEY, the
/// `dns-root-data` package ships DNSKEY (`root.key`) and DS (`root.ds`).
#[derive(Debug, Clone)]
pub enum TrustAnchorKey {
    Dnskey(DnskeyRecord),

    Ds(DsRecord),
}

#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub domain: String,

    pub key: TrustAnchorKey,

    pub description: String,
}

impl TrustAnchor {
    pub fn new(domain: &str, key: TrustAnchorKey, description: String) -> Self {
        Self {
            domain: normalize_domain(domain),
            key,
            description,
        }
    }

    pub fn key_tag(&self) -> u16 {
        match &self.key {
            TrustAnchorKey::Dnskey(dnskey) => dnskey.calculate_key_tag(),
            TrustAnchorKey::Ds(ds) => ds.key_tag,
        }
    }

    pub fn algorithm(&self) -> u8 {
        match &self.key {
            TrustAnchorKey::Dnskey(dnskey) => dnskey.algorithm,
            TrustAnchorKey::Ds(ds) => ds.algorithm,
        }
    }

    /// Whether `dnskey` is the key this anchor pins.
    ///
    /// A DS anchor recomputes the digest over the candidate key (RFC 4034
    /// §5.1.4) via the same verifier the delegation walk uses; a digest we
    /// cannot compute (unsupported type) simply does not match.
    pub fn matches(&self, dnskey: &DnskeyRecord) -> bool {
        match &self.key {
            TrustAnchorKey::Dnskey(anchor_key) => {
                anchor_key.algorithm == dnskey.algorithm
                    && anchor_key.public_key == dnskey.public_key
                    && anchor_key.calculate_key_tag() == dnskey.calculate_key_tag()
            }
            TrustAnchorKey::Ds(ds) => SignatureVerifier
                .verify_ds(ds, dnskey, &self.domain)
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorStore {
    pub fn new() -> Self {
        Self {
            anchors: Self::default_root_anchors(),
        }
    }

    pub fn empty() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    pub fn from_anchors(anchors: Vec<TrustAnchor>) -> Self {
        Self { anchors }
    }

    /// Loads anchors from a file in DNS presentation format, replacing (not
    /// extending) the embedded set — an operator must be able to *remove* an
    /// anchor, not only add one.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DomainError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| {
            DomainError::ConfigError(format!(
                "failed to read trust anchor file {}: {e}",
                path.display()
            ))
        })?;

        text.parse()
    }

    /// The IANA root trust anchors, in DS form exactly as published in
    /// `root-anchors.xml`.
    ///
    /// Both currently-valid anchors ship. KSK-2017 signs the root today;
    /// KSK-2024 is already published and is scheduled to take over signing on
    /// 2026-10-11, after which only it can authenticate the root DNSKEY RRset.
    /// Carrying both means the switchover needs no operator action. The retired
    /// KSK-2010 (key tag 19036) is deliberately omitted — its `validUntil`
    /// passed in 2019.
    pub fn default_root_anchors() -> Vec<TrustAnchor> {
        vec![
            embedded_root_anchor(
                20326,
                "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
                "Root KSK-2017 (20326)",
            ),
            embedded_root_anchor(
                38696,
                "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                "Root KSK-2024 (38696)",
            ),
        ]
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors.iter()
    }

    pub fn has_anchor_for(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.anchors.iter().any(|anchor| anchor.domain == domain)
    }

    /// The keys of `keys` that some anchor for `domain` pins.
    ///
    /// Returns every match rather than the first: during a KSK rollover the zone
    /// publishes the outgoing and incoming keys side by side for months, and
    /// either may be the one that actually signed the DNSKEY RRset.
    pub fn anchor_keys_present<'a>(
        &self,
        domain: &str,
        keys: &'a [DnskeyRecord],
    ) -> Vec<&'a DnskeyRecord> {
        let domain = normalize_domain(domain);
        keys.iter()
            .filter(|key| self.matches_any(&domain, key))
            .collect()
    }

    /// The live key-signing keys of `domain` that no anchor pins — i.e. keys we
    /// would be unable to validate with if the zone started signing with them.
    /// Drives the rollover early warning.
    pub fn unanchored_ksks<'a>(
        &self,
        domain: &str,
        keys: &'a [DnskeyRecord],
    ) -> Vec<&'a DnskeyRecord> {
        let domain = normalize_domain(domain);
        keys.iter()
            .filter(|key| {
                key.is_ksk() && key.flags & REVOKE_FLAG == 0 && !self.matches_any(&domain, key)
            })
            .collect()
    }

    fn matches_any(&self, normalized_domain: &str, key: &DnskeyRecord) -> bool {
        self.anchors
            .iter()
            .any(|anchor| anchor.domain == normalized_domain && anchor.matches(key))
    }
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for TrustAnchorStore {
    type Err = DomainError;

    /// Parses trust anchors in DNS presentation format — the shape written by
    /// `unbound-anchor -a` and shipped by the `dns-root-data` package. Blank
    /// lines and `;` comments are ignored; every other line must be a complete
    /// single-line DS or DNSKEY record.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut anchors = Vec::new();

        for (index, raw_line) in s.lines().enumerate() {
            let line = raw_line.split(';').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let anchor = parse_anchor_line(line).map_err(|e| {
                DomainError::ConfigError(format!("trust anchor line {}: {e}", index + 1))
            })?;
            anchors.push(anchor);
        }

        if anchors.is_empty() {
            return Err(DomainError::ConfigError(
                "trust anchor file contains no DS or DNSKEY record".into(),
            ));
        }

        Ok(Self { anchors })
    }
}

fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim();

    if domain.is_empty() || domain == "." {
        return ".".to_string();
    }

    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    }
}

fn embedded_root_anchor(key_tag: u16, digest_hex: &str, description: &str) -> TrustAnchor {
    const ALGORITHM_RSASHA256: u8 = 8;
    const DIGEST_SHA256: u8 = 2;

    let digest = HEXLOWER_PERMISSIVE
        .decode(digest_hex.as_bytes())
        .expect("embedded root trust anchor digest must be valid hex");

    let ds = ds_from_parts(key_tag, ALGORITHM_RSASHA256, DIGEST_SHA256, digest)
        .expect("embedded root trust anchor must be a valid DS record");

    TrustAnchor::new(".", TrustAnchorKey::Ds(ds), description.to_string())
}

fn parse_anchor_line(line: &str) -> Result<TrustAnchor, String> {
    let tokens: Vec<&str> = line
        .split_whitespace()
        .filter(|token| *token != "(" && *token != ")")
        .collect();

    // Everything between the owner name and the type token is an optional TTL
    // and class, in either order — so locate the type instead of counting.
    let type_index = tokens
        .iter()
        .skip(1)
        .position(|token| token.eq_ignore_ascii_case("DS") || token.eq_ignore_ascii_case("DNSKEY"))
        .map(|index| index + 1)
        .ok_or_else(|| "expected a DS or DNSKEY record".to_string())?;

    let owner = tokens[0];
    let record_type = tokens[type_index];
    let rdata = &tokens[type_index + 1..];

    if record_type.eq_ignore_ascii_case("DS") {
        let (key_tag, algorithm, digest_type) = parse_leading_fields(rdata, "DS")?;
        let digest = HEXLOWER_PERMISSIVE
            .decode(rdata[3..].concat().as_bytes())
            .map_err(|e| format!("invalid DS digest: {e}"))?;

        let ds = ds_from_parts(key_tag, algorithm, digest_type, digest).map_err(record_error)?;
        let description = format!("{owner} DS {key_tag}");

        Ok(TrustAnchor::new(owner, TrustAnchorKey::Ds(ds), description))
    } else {
        let (flags, protocol, algorithm) = parse_leading_fields(rdata, "DNSKEY")?;
        let public_key = STANDARD
            .decode(rdata[3..].concat())
            .map_err(|e| format!("invalid DNSKEY public key: {e}"))?;

        let dnskey =
            dnskey_from_parts(flags, protocol, algorithm, public_key).map_err(record_error)?;
        let description = format!("{owner} DNSKEY {}", dnskey.calculate_key_tag());

        Ok(TrustAnchor::new(
            owner,
            TrustAnchorKey::Dnskey(dnskey),
            description,
        ))
    }
}

/// Unwraps the record parser's own message, so a malformed file is not reported
/// to the operator as an "Invalid DNS response".
fn record_error(error: DomainError) -> String {
    match error {
        DomainError::InvalidDnsResponse(message) => message,
        other => other.to_string(),
    }
}

/// Both record types start with a `u16` followed by two `u8`s (DS: key tag,
/// algorithm, digest type — DNSKEY: flags, protocol, algorithm), then a single
/// encoded blob that presentation format may split across whitespace.
fn parse_leading_fields(rdata: &[&str], record_type: &str) -> Result<(u16, u8, u8), String> {
    if rdata.len() < 4 {
        return Err(format!(
            "{record_type} record has {} fields, expected at least 4",
            rdata.len()
        ));
    }

    let first = rdata[0]
        .parse::<u16>()
        .map_err(|e| format!("invalid {record_type} field 1: {e}"))?;
    let second = rdata[1]
        .parse::<u8>()
        .map_err(|e| format!("invalid {record_type} field 2: {e}"))?;
    let third = rdata[2]
        .parse::<u8>()
        .map_err(|e| format!("invalid {record_type} field 3: {e}"))?;

    Ok((first, second, third))
}

/// Assembles wire-format RDATA and hands it to the record parser, so a
/// file-sourced anchor gets exactly the validation an on-the-wire record does.
fn ds_from_parts(
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
) -> Result<DsRecord, DomainError> {
    let mut rdata = Vec::with_capacity(4 + digest.len());
    rdata.extend_from_slice(&key_tag.to_be_bytes());
    rdata.push(algorithm);
    rdata.push(digest_type);
    rdata.extend_from_slice(&digest);

    DsRecord::parse(&rdata)
}

fn dnskey_from_parts(
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>,
) -> Result<DnskeyRecord, DomainError> {
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(&public_key);

    DnskeyRecord::parse(&rdata)
}
