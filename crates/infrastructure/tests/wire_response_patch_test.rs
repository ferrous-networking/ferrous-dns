use ferrous_dns_infrastructure::dns::wire_response::patch_wire_id;

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
