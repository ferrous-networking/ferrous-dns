---
name: verify
description: The canonical day-to-day local gate for ferrous-dns — superset of `make ci` (fmt-check, clippy -D warnings, tests) plus doc tests, with failures reported for root-cause fixes. Use before marking implementation work done, before committing, or when the user asks to verify changes.
---

Run the local CI gate for ferrous-dns, in this order, and stop at the first failing step to report it:

1. `make fmt-check` — formatting must be clean (`cargo fmt --all -- --check`). If it fails, run `make fmt` and re-check.
2. `make clippy` — `cargo clippy --all-targets --all-features -- -D warnings`. Warnings are denied; every lint must be fixed, not allowed.
3. `make test` — `cargo test --all-features --workspace`. The suite binds `127.0.0.1:0`, so no root or port 53 is needed. Competitor/performance tests are `#[ignore]`d by design.
4. `cargo test --doc --all-features --workspace` — doc tests run separately in CI, so `make test` passing alone is not enough.

If a step fails: read the failure, fix the root cause in the code (do not silence lints or delete tests), and re-run from that step. Report the final status of each of the four steps plainly — green or, if still failing, the exact error.

Do not run fuzz targets here; they need nightly + cargo-fuzz and are covered separately (`make fuzz-short`).
