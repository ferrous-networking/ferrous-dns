# Build and test parallelism

On the host, cargo never gets every core. Build jobs and test threads stay at half the logical CPUs, rounded up, so the machine stays usable. Only CI uses every core; CI runs with `CI` set (GitHub Actions sets `CI=true`).

- Prefer the `make` targets (`make test`, `make clippy`, `make ci`, `make bench`). The Makefile already exports `CARGO_BUILD_JOBS` and `RUST_TEST_THREADS` at half, or at every core under `CI`.
- Any direct cargo command that compiles or runs tests (`build`, `test`, `clippy`, `bench`, `run`, `tarpaulin`) sets both variables itself. That includes the raw commands in `/pre-pr`, `/review-pr` and `/verify`:
  `CARGO_BUILD_JOBS=$(( ($(nproc) + 1) / 2 )) RUST_TEST_THREADS=$(( ($(nproc) + 1) / 2 )) cargo test --workspace --all-features`
- On the host, never use `JOBS=all`, or a `-j` or `--test-threads` above half, unless the user asks for it.
- Concurrent builds share the same cores, and two at half already take them all. Run one build at a time, worktree agents included.
