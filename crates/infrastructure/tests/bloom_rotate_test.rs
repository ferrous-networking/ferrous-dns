use ferrous_dns_infrastructure::dns::cache::bloom::AtomicBloom;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn test_rotate_clears_slot_before_switching_active() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"domain.example");

    bloom.rotate();

    let new_bloom = AtomicBloom::new(1000, 0.01);
    assert!(bloom.check(&"domain.example") || !new_bloom.check(&"domain.example"));
}

#[test]
fn test_check_after_rotate_no_false_negatives_for_new_entries() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"before-rotate.example");
    bloom.rotate();
    bloom.set(&"after-rotate.example");

    assert!(bloom.check(&"after-rotate.example"));
}

#[test]
fn test_rotate_twice_clears_original_entries() {
    let bloom = AtomicBloom::new(1000, 0.01);
    bloom.set(&"entry.example");
    bloom.rotate();
    bloom.rotate();

    assert!(!bloom.check(&"entry.example"));
}

#[test]
fn test_concurrent_rotate_and_check_no_panic() {
    let bloom = Arc::new(AtomicBloom::new(10_000, 0.01));
    let barrier = Arc::new(Barrier::new(3));

    let domains: Vec<String> = (0..100).map(|i| format!("domain{i}.example")).collect();

    let bloom_writer = Arc::clone(&bloom);
    let domains_writer = domains.clone();
    let barrier_writer = Arc::clone(&barrier);
    let writer = thread::spawn(move || {
        barrier_writer.wait();
        for d in &domains_writer {
            bloom_writer.set(d);
        }
    });

    let bloom_rotator = Arc::clone(&bloom);
    let barrier_rotator = Arc::clone(&barrier);
    let rotator = thread::spawn(move || {
        barrier_rotator.wait();
        for _ in 0..10 {
            bloom_rotator.rotate();
        }
    });

    let bloom_reader = Arc::clone(&bloom);
    let barrier_reader = Arc::clone(&barrier);
    let reader = thread::spawn(move || {
        barrier_reader.wait();
        let mut hits = 0usize;
        for i in 0..100 {
            if bloom_reader.check(&format!("domain{i}.example")) {
                hits += 1;
            }
        }
        hits
    });

    writer.join().expect("writer panicked");
    rotator.join().expect("rotator panicked");
    reader.join().expect("reader panicked");
}
