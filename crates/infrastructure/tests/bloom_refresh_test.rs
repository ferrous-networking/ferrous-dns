use ferrous_dns_infrastructure::dns::cache::bloom::AtomicBloom;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn refresh_sets_bits_when_not_present_in_active_slot() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.refresh(&"new.example");
    assert!(bloom.check(&"new.example"));
}

#[test]
fn refresh_on_warm_entry_keeps_it_visible() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"warm.example");
    bloom.refresh(&"warm.example");
    assert!(bloom.check(&"warm.example"));
}

#[test]
fn refresh_entry_survives_second_rotation_where_set_alone_would_not() {
    // After set + rotate, entry is in the inactive slot only.
    // refresh moves bits into the new active slot so it survives a second rotate.
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"survive.example");
    bloom.rotate();
    // Still visible (inactive slot has bits)
    assert!(bloom.check(&"survive.example"));
    // Refresh promotes bits into the now-active slot
    bloom.refresh(&"survive.example");
    // Second rotation clears the slot that held the original bits
    bloom.rotate();
    assert!(
        bloom.check(&"survive.example"),
        "refresh must keep entry alive through second rotation"
    );
}

#[test]
fn without_refresh_entry_disappears_after_two_rotations() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"stale.example");
    bloom.rotate();
    bloom.rotate();
    assert!(!bloom.check(&"stale.example"));
}

#[test]
fn refresh_is_idempotent_on_fully_warm_entry() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"idempotent.example");
    bloom.refresh(&"idempotent.example");
    bloom.refresh(&"idempotent.example");
    assert!(bloom.check(&"idempotent.example"));
}

#[test]
fn refresh_does_not_affect_other_entries() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"a.example");
    bloom.set(&"b.example");
    bloom.refresh(&"a.example");
    assert!(bloom.check(&"b.example"), "refreshing a must not evict b");
}

#[test]
fn concurrent_refresh_and_rotate_no_panic() {
    let bloom = Arc::new(AtomicBloom::new(10_000, 0.01));
    let barrier = Arc::new(Barrier::new(3));

    let domains: Vec<String> = (0..100).map(|i| format!("r{i}.example")).collect();
    for d in &domains {
        bloom.set(d);
    }

    let bloom_refresher = Arc::clone(&bloom);
    let domains_r = domains.clone();
    let barrier_r = Arc::clone(&barrier);
    let refresher = thread::spawn(move || {
        barrier_r.wait();
        for d in &domains_r {
            bloom_refresher.refresh(d);
        }
    });

    let bloom_rotator = Arc::clone(&bloom);
    let barrier_rot = Arc::clone(&barrier);
    let rotator = thread::spawn(move || {
        barrier_rot.wait();
        for _ in 0..5 {
            bloom_rotator.rotate();
        }
    });

    let bloom_reader = Arc::clone(&bloom);
    let barrier_rd = Arc::clone(&barrier);
    let reader = thread::spawn(move || {
        barrier_rd.wait();
        for i in 0..100 {
            let _ = bloom_reader.check(&format!("r{i}.example"));
        }
    });

    refresher.join().expect("refresher panicked");
    rotator.join().expect("rotator panicked");
    reader.join().expect("reader panicked");
}
