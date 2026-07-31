//! Trust anchor parsing, DS matching, and root KSK rollover behaviour.
//!
//! The key blobs and digests below are the IANA root anchors verbatim from
//! <https://data.iana.org/root-anchors/root-anchors.xml>: KSK-2017 (20326),
//! which signs the root today, and KSK-2024 (38696), which takes over on
//! 2026-10-11.

use base64::{engine::general_purpose::STANDARD, Engine};
use ferrous_dns_domain::{RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::{
    ChainVerifier, DnskeyRecord, DnssecCache, TrustAnchorKey, TrustAnchorStore, ValidationResult,
};
use ferrous_dns_infrastructure::dns::{PoolManager, QueryEventEmitter};
use std::str::FromStr;
use std::sync::Arc;

const KSK_2017_B64: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
const KSK_2024_B64: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";

const KSK_2017_DS: &str = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
const KSK_2024_DS: &str = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

fn dnskey(flags: u16, key_b64: &str) -> DnskeyRecord {
    DnskeyRecord {
        flags,
        protocol: 3,
        algorithm: 8,
        public_key: STANDARD.decode(key_b64).expect("valid base64 key"),
    }
}

fn ksk_2017() -> DnskeyRecord {
    dnskey(257, KSK_2017_B64)
}

fn ksk_2024() -> DnskeyRecord {
    dnskey(257, KSK_2024_B64)
}

/// A root ZSK stand-in: right shape, key material no anchor pins.
fn root_zsk() -> DnskeyRecord {
    DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 8,
        public_key: vec![0x03, 0x01, 0x00, 0x01, 0xAB, 0xCD],
    }
}

fn ds_anchor_store(anchors: &[(u16, &str)]) -> TrustAnchorStore {
    let text: String = anchors
        .iter()
        .map(|(key_tag, digest)| format!(". IN DS {key_tag} 8 2 {digest}\n"))
        .collect();

    TrustAnchorStore::from_str(&text).expect("valid anchor file")
}

fn key_tags(keys: &[&DnskeyRecord]) -> Vec<u16> {
    keys.iter().map(|key| key.calculate_key_tag()).collect()
}

#[test]
fn embedded_set_carries_both_current_root_anchors() {
    let store = TrustAnchorStore::new();

    assert_eq!(store.len(), 2);
    assert_eq!(
        store.iter().map(|a| a.key_tag()).collect::<Vec<_>>(),
        vec![20326, 38696]
    );
    assert!(store
        .iter()
        .all(|anchor| matches!(anchor.key, TrustAnchorKey::Ds(_))));
    assert!(store.has_anchor_for("."));
    assert!(store.has_anchor_for(""));
}

#[test]
fn embedded_ds_anchors_match_their_published_keys() {
    let store = TrustAnchorStore::new();
    let keys = [ksk_2017(), root_zsk(), ksk_2024()];

    assert_eq!(
        key_tags(&store.anchor_keys_present(".", &keys)),
        vec![20326, 38696]
    );
}

#[test]
fn anchors_do_not_cover_a_zone_they_were_not_issued_for() {
    let store = TrustAnchorStore::new();

    assert!(!store.has_anchor_for("com."));
    assert!(store.anchor_keys_present("com.", &[ksk_2024()]).is_empty());
}

/// The failure this whole change exists to prevent: with only the outgoing
/// anchor configured, the incoming KSK is invisible, so the root DNSKEY RRset
/// stops being verifiable the moment the root signs with it.
#[test]
fn a_single_anchor_covers_only_its_own_key() {
    let store = ds_anchor_store(&[(20326, KSK_2017_DS)]);
    let keys = [ksk_2017(), ksk_2024()];

    let matched = store.anchor_keys_present(".", &keys);
    assert_eq!(key_tags(&matched), vec![20326]);
}

#[test]
fn two_anchors_cover_both_keys_across_a_rollover() {
    let store = ds_anchor_store(&[(20326, KSK_2017_DS), (38696, KSK_2024_DS)]);
    let keys = [ksk_2017(), root_zsk(), ksk_2024()];

    let matched = store.anchor_keys_present(".", &keys);
    assert_eq!(key_tags(&matched), vec![20326, 38696]);
}

#[test]
fn unanchored_ksks_flags_the_incoming_key_only() {
    let store = ds_anchor_store(&[(20326, KSK_2017_DS)]);
    let keys = [ksk_2017(), root_zsk(), ksk_2024()];

    let unanchored = store.unanchored_ksks(".", &keys);
    assert_eq!(
        key_tags(&unanchored),
        vec![38696],
        "the ZSK must not be reported — only key-signing keys can be anchored"
    );
}

#[test]
fn unanchored_ksks_is_quiet_when_every_ksk_is_anchored() {
    let store = TrustAnchorStore::new();

    assert!(store
        .unanchored_ksks(".", &[ksk_2017(), root_zsk(), ksk_2024()])
        .is_empty());
}

#[test]
fn a_revoked_key_is_not_reported_as_unanchored() {
    let store = ds_anchor_store(&[(38696, KSK_2024_DS)]);
    let revoked_ksk_2017 = dnskey(257 | 0x0080, KSK_2017_B64);

    assert!(store
        .unanchored_ksks(".", &[revoked_ksk_2017, ksk_2024()])
        .is_empty());
}

#[test]
fn parses_a_ds_line() {
    let store =
        TrustAnchorStore::from_str(&format!(".\t172800\tIN\tDS\t20326 8 2 {KSK_2017_DS}\n"))
            .unwrap();

    assert_eq!(store.len(), 1);
    let anchor = store.iter().next().unwrap();
    assert_eq!(anchor.key_tag(), 20326);
    assert_eq!(anchor.algorithm(), 8);
    assert!(anchor.matches(&ksk_2017()));
    assert!(!anchor.matches(&ksk_2024()));
}

#[test]
fn parses_a_dnskey_line_with_a_trailing_comment() {
    let line = format!(
        ".\t172800\tIN\tDNSKEY\t257 3 8 {KSK_2017_B64}  ;{{id = 20326 (ksk), size = 2048b}}\n"
    );

    let store = TrustAnchorStore::from_str(&line).unwrap();
    let anchor = store.iter().next().unwrap();
    assert!(matches!(anchor.key, TrustAnchorKey::Dnskey(_)));
    assert_eq!(anchor.key_tag(), 20326);
    assert!(anchor.matches(&ksk_2017()));
    assert!(!anchor.matches(&ksk_2024()));
}

#[test]
fn joins_rdata_split_across_whitespace() {
    let (head, tail) = KSK_2024_DS.split_at(32);

    let store = TrustAnchorStore::from_str(&format!(". IN DS 38696 8 2 {head} {tail}\n")).unwrap();
    assert!(store.iter().next().unwrap().matches(&ksk_2024()));
}

#[test]
fn accepts_a_file_mixing_both_forms_and_ignores_noise() {
    let text = format!(
        "; IANA root trust anchors\n\
         \n\
         . 172800 IN DS 20326 8 2 {KSK_2017_DS}\n\
         ; the incoming key, published but not yet signing\n\
         .\tIN\tDNSKEY\t257 3 8 {KSK_2024_B64}\n"
    );

    let store = TrustAnchorStore::from_str(&text).unwrap();
    assert_eq!(store.len(), 2);
    assert_eq!(
        key_tags(&store.anchor_keys_present(".", &[ksk_2017(), ksk_2024()])),
        vec![20326, 38696]
    );
}

#[test]
fn rejects_a_file_without_anchors() {
    assert!(TrustAnchorStore::from_str("; only a comment\n\n").is_err());
    assert!(TrustAnchorStore::from_str("").is_err());
}

#[test]
fn rejects_a_digest_of_the_wrong_length() {
    let err = TrustAnchorStore::from_str(". IN DS 20326 8 2 DEADBEEF\n").unwrap_err();

    assert!(
        err.to_string().contains("line 1"),
        "the error should name the offending line: {err}"
    );
}

#[test]
fn rejects_an_unsupported_record_type() {
    assert!(TrustAnchorStore::from_str(". IN A 192.0.2.1\n").is_err());
}

#[test]
fn rejects_a_truncated_record() {
    assert!(TrustAnchorStore::from_str(". IN DS 20326 8\n").is_err());
}

#[test]
fn loads_anchors_from_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.ds");
    std::fs::write(&path, format!(". IN DS 38696 8 2 {KSK_2024_DS}\n")).unwrap();

    let store = TrustAnchorStore::from_file(&path).unwrap();
    assert_eq!(store.len(), 1);
    assert!(store.iter().next().unwrap().matches(&ksk_2024()));
}

#[test]
fn reports_a_missing_file_by_path() {
    let err = TrustAnchorStore::from_file("/nonexistent/ferrous-dns-root.key").unwrap_err();

    assert!(err
        .to_string()
        .contains("/nonexistent/ferrous-dns-root.key"));
}

async fn live_root_chain_verifier() -> ChainVerifier {
    let pool = UpstreamPool {
        name: "live".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://1.1.1.1:53".into()],
        weight: None,
    };

    let pool_manager = Arc::new(
        PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled())
            .await
            .unwrap(),
    );

    ChainVerifier::new(
        pool_manager,
        TrustAnchorStore::new(),
        Arc::new(DnssecCache::new()),
    )
}

/// The real check on the embedded digests: bootstrap the root from them against
/// the live root DNSKEY RRset. Validating `.` alone stops right after the
/// bootstrap, so a failure here is about the anchors and nothing else.
#[tokio::test]
#[ignore = "live network: hits 1.1.1.1 and the root zone; run with --ignored"]
async fn live_embedded_anchors_bootstrap_the_root() {
    let mut verifier = live_root_chain_verifier().await;

    let result = verifier
        .verify_chain(".", RecordType::DNSKEY)
        .await
        .unwrap();
    assert_eq!(result, ValidationResult::Secure);

    let root_keys = verifier
        .get_zone_keys(".")
        .expect("root DNSKEY RRset bootstrapped")
        .clone();

    // KSK-2024 is published now and takes over signing on 2026-10-11, so its
    // digest must match a live key or what we ship is wrong. KSK-2017 is
    // deliberately not asserted — it leaves the RRset once the rollover ends.
    let ksk_2024_anchor = TrustAnchorStore::default_root_anchors()
        .into_iter()
        .find(|anchor| anchor.key_tag() == 38696)
        .expect("KSK-2024 anchor is embedded");

    assert!(
        root_keys.iter().any(|key| ksk_2024_anchor.matches(key)),
        "the embedded KSK-2024 digest matches no live root DNSKEY"
    );
}
