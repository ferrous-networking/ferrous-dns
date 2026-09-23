---
name: deadlock-tests-need-timeout-guard
description: Regression-test a deadlock behind a thread plus recv_timeout, never by calling the code directly — a hang blocks CI instead of failing it
type: feedback
---

A test that calls deadlocking code directly hangs the test binary: CI burns its
whole timeout and reports nothing useful. Run the suspect call on its own thread
and assert on a channel receive with a timeout, so the failure arrives as a named
assertion.

**Why:** the failure mode of a lock bug is silence. A red suite that names the
broken invariant is worth more than a job that dies on the global timeout — and
it is what makes "commit the reproduction red first" practical at all.

**How to apply:**

```rust
fn run_with_deadlock_guard<F: FnOnce() + Send + 'static>(label: &str, f: F) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || { f(); let _ = tx.send(()); });
    assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok(), "{label} deadlocked");
}
```

Put the subject in an `Arc`, clone it into the closure, and assert on the outer
handle after the guard returns. Precedents in the repo:
`crates/infrastructure/tests/cache_eviction_fallback_test.rs` (the whole file,
issue #228), `local_record_nodata_test.rs:296`,
`cache_layer_inflight_toctou_test.rs:368`.

Cache-specific gotcha when asserting afterwards: `cache.get()` can be served by
the thread-local L1 and mask a removal from the backing map. Assert on
`cache.size()`, or use CNAME data, which never enters L1.
Related: [[cache-eviction-random-branch-deadlock]].
