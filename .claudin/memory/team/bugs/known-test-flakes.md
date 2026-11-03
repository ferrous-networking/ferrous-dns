---
name: known-test-flakes
description: Four tests have each failed once and passed on rerun — three around a minute/hour boundary or an unknown race, one on the free_port AddrInUse race; seen 2026-10-28 → 11-01, none filed
type: project
paths:
  - crates/infrastructure/tests/query_log_hour_rollup_job_test.rs
  - crates/api-pihole/tests/action_tests.rs
  - crates/infrastructure/tests/conditional_forwarding_test.rs
  - crates/cli/tests/server_process/mod.rs
  - crates/infrastructure/src/repositories/query_log_repository/rollup.rs
---

**Symptom:** CI or `make ci` fails on one of the tests below, and a rerun is green. Rerun before you chase a regression. A test that fails twice in a row is a real failure.

**Where, and what was seen:**
- `query_log_hour_rollup_job_test.rs` `test_roll_up_waits_for_the_query_log_writer_instead_of_failing_busy` got `Ok(0)` instead of `Ok(1)` at 18:00 UTC on 2026-10-28. The row is inserted "an hour ago" from one `Utc::now()` read, and the job picks its hour from a later one. The likely cause, not confirmed, is an hour boundary between the two reads.
- api-pihole `action_tests.rs` `flush_logs_clears_query_log_entries` left one `query_log_minute` row on #348's CI (2026-10-28 15:56:00 UTC). `prune_before` (`rollup.rs:266`) deletes `bucket < cutoff`, so a flush at second :00 keeps the minute bucket that starts at the cutoff. Production has the same edge: a flush at :00 keeps that minute's rollup counts.
- `conditional_forwarding_test.rs` `test_routed_reverse_zone_beats_the_local_dns_server_for_private_ptrs` (`:176`, got NxDomain) failed on main's CI coverage job at `95617f9b` (2026-10-28). The same tree passed on #348's CI. The cause was not found.
- `server_process/mod.rs` `free_port` binds a TCP and a UDP socket to find a port, then drops both before the spawned server binds it. Another process can take the port in between, and the server dies with AddrInUse. `healthcheck_test` hit it once on each of the #354 and #355 branches (2026-11-01), and each time 3 reruns passed.

**Repro:** none on demand, since they depend on timing. For the two clock cases, run them with the clock just before a boundary (:59:59).

**Status:** open and unfiled as of 2026-11-01.

**Why not fixed:** each one showed up while working on another PR and was left out of its scope.
