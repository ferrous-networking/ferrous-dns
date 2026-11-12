---
name: known-test-flakes
description: Tests that failed and then passed on rerun, with cause and status. #377 fixed the UDP-pool runtime race and the TCP reconnect bound (2026-11-09); the hour-boundary rollup test, the flush-at-:00 edge and the free_port AddrInUse race are open and unfiled
type: project
paths:
  - crates/infrastructure/tests/query_log_hour_rollup_job_test.rs
  - crates/api-pihole/tests/action_tests.rs
  - crates/infrastructure/tests/conditional_forwarding_test.rs
  - crates/infrastructure/tests/upstream_rcode_test.rs
  - crates/infrastructure/tests/dns_transport_test.rs
  - crates/cli/tests/server_process/mod.rs
  - crates/infrastructure/src/repositories/query_log_repository/rollup.rs
  - crates/infrastructure/src/dns/transport/udp_pool.rs
---

**Symptom:** CI or `make ci` fails on one of the tests below, and a rerun is green. Rerun before you chase a regression. Two failures in a row usually mean a real failure. The `free_port` race is the exception: on 2026-11-05 it failed twice in a row.

**Open:**
- `query_log_hour_rollup_job_test.rs` `test_roll_up_waits_for_the_query_log_writer_instead_of_failing_busy` got `Ok(0)` instead of `Ok(1)`. That happened at 18:00 UTC on 2026-10-28, again on 2026-11-08 in a local full run that crossed 04:00 UTC, and at 23:00 UTC on 2026-11-09 in #385's full run. The test inserts the row "an hour ago" based on one `Utc::now()` read, and the job picks its hour from a later read. The likely cause is an hour boundary falling between the two reads. All three failures fell on a boundary, but no run has reproduced it on demand.
- api-pihole `action_tests.rs` `flush_logs_clears_query_log_entries` left one `query_log_minute` row on #348's CI (2026-10-28 15:56:00 UTC). `prune_before` (`rollup.rs:266` on 10-28) deletes `bucket < cutoff`, so a flush at second :00 keeps the minute bucket that starts at the cutoff. Production has the same edge: a flush at :00 keeps that minute's rollup counts.
- `server_process/mod.rs` `free_port` binds a TCP and a UDP socket to find a free port, then drops both before the spawned server binds it. Another process can take the port in between, and the server then dies with AddrInUse. `healthcheck_test` hit this once on each of the #354 and #355 branches (2026-11-01). On 2026-11-05, `test_healthcheck_exits_1_while_the_dns_port_is_taken` failed in 3 of 8 local full runs, twice in a row on the #371 branch. It has never failed on GitHub CI.

**Fixed by #377 (`b2d1821d`, merged 2026-11-09):**
- `conditional_forwarding_test.rs` `test_routed_reverse_zone_beats_the_local_dns_server_for_private_ptrs` got NxDomain on main's coverage job, at `95617f9b` (2026-10-28) and again at `b7904e7b` (2026-11-08).
  - Cause: `UdpSocketPool` is a process static, but a tokio socket only works on the runtime that registered it. A `#[tokio::test]` whose fake upstream reused a finished test's ephemeral port got that test's parked socket. The send then failed with "A Tokio 1.x context was found, but it is being shutdown".
  - Fix: the pool is now keyed by `(runtime id, server)`. Before the fix it reproduced in 1 of 400 runs with `taskset -c 0`; after the fix, 0 of 2,000.
  - TCP never had the problem, because a dead pooled connection reconnects.
- `upstream_rcode_test.rs` `failover_moves_past_a_refusing_server` failed at `:208` on #372's coverage job (2026-11-07) and passed in the Test job. It spawns UDP fake upstreams on `127.0.0.1:0` under `#[tokio::test]`, so it was exposed to the same pool race. That the race caused this failure is inferred, not confirmed.
- `dns_transport_test.rs` `tcp_transport_reconnect_stays_within_the_query_timeout` took 637 ms against a 600 ms bound on #377's coverage job. The bound is now 2× the timeout, the least a broken reconnect costs.

**Repro:** none on demand for the open ones, since they depend on timing. For the two clock cases, run the tests with the clock just before a boundary (:59:59).

**Status:** the open ones are unfiled as of 2026-11-09.

**Why not fixed:** each one showed up during work on another PR and was out of that PR's scope.
