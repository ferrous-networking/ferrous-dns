use ferrous_dns_infrastructure::dns::wire_response::{
    patch_wire_id, patch_wire_id_clear_ad, set_ad_bit,
};

#[test]
fn patch_wire_id_overwrites_first_two_bytes() {
    let wire = vec![0x00, 0x00, 0xAA, 0xBB, 0xCC];
    let patched = patch_wire_id(&wire, 0x1234).expect("should return Some");
    assert_eq!(patched[0], 0x12);
    assert_eq!(patched[1], 0x34);
    assert_eq!(&patched[2..], &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn patch_wire_id_does_not_modify_original() {
    let wire = vec![0x00, 0x00, 0xFF];
    let _ = patch_wire_id(&wire, 0xBEEF);
    assert_eq!(wire[0], 0x00);
    assert_eq!(wire[1], 0x00);
}

#[test]
fn patch_wire_id_returns_none_for_empty_slice() {
    assert!(patch_wire_id(&[], 0x1234).is_none());
}

#[test]
fn patch_wire_id_returns_none_for_one_byte_slice() {
    assert!(patch_wire_id(&[0xFF], 0x1234).is_none());
}

#[test]
fn patch_wire_id_works_for_exactly_two_bytes() {
    let wire = vec![0x00, 0x00];
    let patched = patch_wire_id(&wire, 0xABCD).expect("two bytes is sufficient");
    assert_eq!(patched, vec![0xAB, 0xCD]);
}

#[test]
fn patch_wire_id_id_zero() {
    let wire = vec![0xFF, 0xFF, 0x01, 0x02];
    let patched = patch_wire_id(&wire, 0x0000).expect("should return Some");
    assert_eq!(patched[0], 0x00);
    assert_eq!(patched[1], 0x00);
    assert_eq!(&patched[2..], &[0x01, 0x02]);
}

// --- patch_wire_id_clear_ad: a non-DO client must NEVER receive AD=1 ---

#[test]
fn patch_wire_id_clear_ad_clears_set_ad_bit() {
    // Byte 3 = 0xA0 has the AD bit (0x20) set; it must come back cleared, and
    // the query ID must still be patched.
    let wire = vec![0x00, 0x00, 0x81, 0xA0, 0xCC];
    let patched = patch_wire_id_clear_ad(&wire, 0x1234).expect("should return Some");
    assert_eq!(patched[0], 0x12);
    assert_eq!(patched[1], 0x34);
    assert_eq!(patched[3] & 0x20, 0x00, "AD bit must be cleared");
    // Other flag bits in byte 3 are untouched (0xA0 & !0x20 == 0x80).
    assert_eq!(patched[3], 0x80);
    assert_eq!(patched[4], 0xCC);
}

#[test]
fn patch_wire_id_clear_ad_leaves_already_clear_ad() {
    let wire = vec![0x00, 0x00, 0x81, 0x80, 0xCC];
    let patched = patch_wire_id_clear_ad(&wire, 0xBEEF).expect("should return Some");
    assert_eq!(patched[3], 0x80);
}

#[test]
fn patch_wire_id_clear_ad_returns_none_for_short_slice() {
    assert!(patch_wire_id_clear_ad(&[0xFF], 0x1234).is_none());
}

// --- set_ad_bit: raw-wire AD override on the slow path ---

#[test]
fn set_ad_bit_sets_and_clears() {
    let mut buf = vec![0x00, 0x00, 0x81, 0x80];
    set_ad_bit(&mut buf, true);
    assert_eq!(buf[3] & 0x20, 0x20, "AD bit must be set");
    set_ad_bit(&mut buf, false);
    assert_eq!(buf[3] & 0x20, 0x00, "AD bit must be cleared");
}

#[test]
fn set_ad_bit_preserves_other_flag_bits() {
    // 0x83 keeps RA + RCODE bits; setting/clearing AD must not disturb them.
    let mut buf = vec![0x00, 0x00, 0x81, 0x83];
    set_ad_bit(&mut buf, true);
    assert_eq!(buf[3], 0xA3);
    set_ad_bit(&mut buf, false);
    assert_eq!(buf[3], 0x83);
}

#[test]
fn set_ad_bit_noop_on_short_buffer() {
    let mut buf = vec![0x00, 0x00, 0x81];
    set_ad_bit(&mut buf, true);
    assert_eq!(buf, vec![0x00, 0x00, 0x81]);
}
