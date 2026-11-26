---
name: known-test-flakes
description: Tests that failed and then passed on rerun, with cause and status. #377 fixed the UDP-pool runtime race and the TCP reconnect bound (2026-11-09); #389 fixed a spawn-timed live test under tarpaulin (11-12); #406 fixed clock-named config files shared by api tests (11-23); the hour-boundary rollup test, the flush-at-:00 edge and the free_port AddrInUse race are open and unfiled
type: project
paths:
  - crates/infrastructure/tests/query_log_hour_rollup_job_test.rs
  - crates/api-pihole/tests/action_tests.rs
  - crates/infrastructure/tests/conditional_forwarding_test.rs
  - crates/infrastructure/tests/upstream_rcode_test.rs
  - crates/infrastructure/tests/dns_transport_test.rs
  - crates/cli/tests/server_process/mod.rs
  - crates/cli/tests/startup_filtering_live_test.rs
  - crates/infrastructure/src/repositories/query_log_repository/rollup.rs
  - crates/infrastructure/src/dns/transport/udp_pool.rs
  - crates/api/tests/helpers/config_file.rs
  - crates/api/tests/config_update_api_tests.rs
---

**Symptom:** CI or `make ci` fails on one of the tests below, and a rerun is green. Rerun before you chase a regression. Two failures in a row usually mean a real failure. The `free_port` race is the exception: on 2026-11-05 it failed twice in a row.

**Open:**
- `query_log_hour_rollup_job_test.rs` `test_roll_up_waits_for_the_query_log_writer_instead_of_failing_busy` got `Ok(0)` instead of `Ok(1)`. That happened at 18:00 UTC on 2026-10-28, again on 2026-11-08 in a local full run that crossed 04:00 UTC, and at 23:00 UTC on 2026-11-09 in #385's full run. The test inserts the row "an hour ago" based on one `Utc::now()` read, and the job picks its hour from a later read. The likely cause is an hour boundary falling between the two reads. All three failures fell on a boundary, but no run has reproduced it on demand.
- api-pihole `action_tests.rs` `flush_logs_clears_query_log_entries` left one `query_log_minute` row on #348's CI (2026-10-28 15:56:00 UTC). `prune_before` (`rollup.rs:266` on 10-28) deletes `bucket < cutoff`, so a flush at second :00 keeps the minute bucket that starts at the cutoff. Production has the same edge: a flush at :00 keeps that minute's rollup counts.
- `server_process/mod.rs` `free_port` binds a TCP and a UDP socket to find a free port, then drops both before the spawned server binds it. Another process can take the port in between, and the server then dies with AddrInUse. `healthcheck_test` hit this once on each of the #354 and #355 branches (2026-11-01). On 2026-11-05, `test_healthcheck_exits_1_while_the_dns_port_is_taken` failed in 3 of 8 local full runs, twice in a row on the #371 branch. On 2026-11-11, on #387's branch, `test_explicit_ipv6_dns_bind_is_reported_while_the_web_stays_up` got an empty HTTP response once in a parallel full run, then passed 8 times in a row; the same race is the likely cause, not confirmed. On 2026-11-13, in a local `make ci`, `dual_stack_bind_live_test.rs` `test_ipv4_bind_address_still_refuses_ipv6` failed with "DNS over TCP on ::1": something answered on `::1` at the port `free_port` had handed out, likely another test's dual-stack server. It then passed 3 times in a row and in a full `--no-fail-fast` run. It has never failed on GitHub CI. Also on 2026-11-13, `healthcheck_test.rs` `test_health_reports_ok_and_the_version_while_dns_listens` got `503 {"status":"unavailable"}` once in a full run and once alone, which fits the DNS port being taken, and `test_healthcheck_exits_1_while_the_dns_port_is_taken` failed 2 times in 10 solo runs on `main` (`10a78b33`) as well. A second signature showed up on #411's Test job (2026-11-23, a pip-only Dependabot bump on `1d503600`, whose main run was green): `startup_filtering_live_test.rs` `test_a_shutdown_during_the_startup_hold_closes_the_database` panicked at `add_blocklist_source` (`:187`, `read_to_string`) with `ConnectionReset`. The test died 48 ms after `running 4 tests`, which is less than `start_with`'s 100 ms poll, so its first connect hit a listener that already held the web port before the binary could bind it. The likely holder is another parallel test's `free_port` probe listener, closed with the probe and the POST still in its accept queue (a listener closed with a queued connection resets it, checked). That holder is inferred, not confirmed. `gh run rerun --failed` was green on 2026-11-25.

**Fixed by #377 (`b2d1821d`, merged 2026-11-09):**
- `conditional_forwarding_test.rs` `test_routed_reverse_zone_beats_the_local_dns_server_for_private_ptrs` got NxDomain on main's coverage job, at `95617f9b` (2026-10-28) and again at `b7904e7b` (2026-11-08).
  - Cause: `UdpSocketPool` is a process static, but a tokio socket only works on the runtime that registered it. A `#[tokio::test]` whose fake upstream reused a finished test's ephemeral port got that test's parked socket. The send then failed with "A Tokio 1.x context was found, but it is being shutdown".
  - Fix: the pool is now keyed by `(runtime id, server)`. Before the fix it reproduced in 1 of 400 runs with `taskset -c 0`; after the fix, 0 of 2,000.
  - TCP never had the problem, because a dead pooled connection reconnects.
- `upstream_rcode_test.rs` `failover_moves_past_a_refusing_server` failed at `:208` on #372's coverage job (2026-11-07) and passed in the Test job. It spawns UDP fake upstreams on `127.0.0.1:0` under `#[tokio::test]`, so it was exposed to the same pool race. That the race caused this failure is inferred, not confirmed.
- `dns_transport_test.rs` `tcp_transport_reconnect_stays_within_the_query_timeout` took 637 ms against a 600 ms bound on #377's coverage job. The bound is now 2× the timeout, the least a broken reconnect costs.

**Fixed in #389 (`4882d489`, 2026-11-12), before merge:**
- `startup_filtering_live_test.rs` `test_a_restart_filters_from_its_first_answer_without_waiting_for_the_host` asserted that the first answer came less than 10 s after the spawn. It failed on the coverage job only, at 11.7 s. Tarpaulin's ptrace made the spawned binary take 9 s to log its first line, and the server answered 0.8 s after it opened its ports.
  - Fix: the test now checks that the list host had not served the list again when the first answer came. It times against an event, not the clock.
  - Rule for live tests: never bound an upper time from the spawn of the binary. Measure from an event the server causes. A lower bound from the spawn cannot flake, but a slow start can make it pass vacuously.
  - Repro: wrap the spawn in `sh -c 'sleep 11; exec "$0" "$@"'`. `strace -f` did not slow the start enough here.

**Repro:** none on demand for the open ones, since they depend on timing. For the two clock cases, run the tests with the clock just before a boundary (:59:59).

**Fixed in #406 (`8e9eaf39`, 2026-11-23, before merge; merged as `13e76d27`):**
- api `config_update_api_tests.rs` `test_reload_keeps_the_running_config_when_the_file_fails_validation` got 200 instead of 500 on #406's Test job (2026-11-22), and passed locally.
  - Cause: the three api config test files named their temp config after `pid + SystemTime nanos`. Parallel tests in one process can read the same tick (Azure runners likely tick in 100 ns), so two tests shared a file and one saved a valid config over the other's invalid one. Inferred from the symptom; forcing a shared name reproduces the exact `200 vs 500` and 14 other failures.
  - Fix: `helpers::empty_config_file(prefix)` names the file after the pid and a process-wide `AtomicU64`. With the counter frozen (`load` instead of `fetch_add`), 15 tests fail; restored, 5 runs in a row passed.
  - Rule: never make a temp name unique with the clock alone. Use a counter, or a per-test tag like `wal_checkpoint_job_tests.rs`.

**Status:** the open ones are unfiled as of 2026-11-12.

**Why not fixed:** each one showed up during work on another PR and was out of that PR's scope.
