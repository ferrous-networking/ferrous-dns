# Team Memory Index

Shared memories for the ferrous-dns team (one file per fact, with `name`/`description`/`type` frontmatter).

<!-- Add one line per memory: - [Title](file.md) — one-line hook -->

- [Cache refresh maximizes coverage](cache-refresh-maximize-coverage.md) — never cap total refresh throughput with a fixed rate; bound concurrency instead
- [Web TLS Secure-cookie invariant](web-tls-secure-cookie-invariant.md) — the cookie's `Secure` flag follows the live transport, never the config flag
- [DnsResolution wire-data invariant](dns-resolution-wire-data-invariant.md) — no `upstream_wire_data` means every non-A/AAAA answer reaches the client empty
- [Runtime verification recipe](runtime-verification-recipe.md) — minimal config to run the binary; enum casing, main×branch, pkill, auth-off curl, UI-save, fake-upstream load
- [Issue #216 blocklist sync](issue-216-blocklist-sync.md) — three defects behind "blocklists not syncing", now fixed; plus why there is no per-source refresh
- [Deadlock tests need a timeout guard](deadlock-tests-need-timeout-guard.md) — run the suspect call on a thread behind `recv_timeout`, so a hang fails CI instead of blocking it
- [`/verify` name collision](verify-skill-name-collision.md) — the Skill tool loads the bundled runtime skill, not this repo's CI gate; run the steps or use `/pre-pr`
- [gh write ops: use REST](gh-write-ops-use-rest.md) — GraphQL reports a phantom rate limit on review/issue creation; `gh api --method POST` works
- [Docs screenshot recipe](docs-screenshot-recipe.md) — how the dashboard screenshots were seeded and captured, the conventions to keep, and which are stale
- [Fuzz workspace is invisible to Dependabot](fuzz-workspace-excluded-from-dependabot.md) — duplicate exact pins in `fuzz/Cargo.toml` break every dependency-group bump
- [Container CVE triage](container-cve-triage.md) — the alpine tag lags its own repo; runtime stages need `apk upgrade`, and the binary never loads the image's libssl
- [Pi-hole compat auth](pihole-compat-auth.md) — read commit `81c1b7b` before changing auth in `crates/api-pihole`
- [Upstream URL parser has a JS mirror](upstream-url-parser-js-mirror.md) — change `DnsProtocol::from_str` and `settings.js` together; stricter parsing needs a legacy.rs pass
- [Pi-hole compat matches FTL exactly](pihole-compat-ftl-mirrors.md) — strict FTL mirror structs in tests/helpers/ftl.rs; C code wins over the YAML; bodies via PiholeJson
- [Don't share target/ across checkouts](shared-target-dir-across-checkouts.md) — building a worktree into the main `target/` leaves stale workspace rlibs; own CARGO_TARGET_DIR on disk (~18 GB, not tmpfs /tmp)
- [Pi-hole compat live validation](pihole-compat-live-validation.md) — diff against a live Pi-hole v6 + run the real integrations in Docker; Homarr :3000 clash, Glance cache traps
- [rg skips CoreResolver](rg-skips-core-rs.md) — `.gitignore` has `core.*`, so Grep/rg never search `resolver/core.rs`; use `no_ignore`
- [Strict docs build vs uncommitted pages](mkdocs-strict-uncommitted-pages.md) — git-revision plugin warns on new uncommitted pages; check with a search-only INHERIT config; serve is under /ferrous-dns/
- [Malware settings have a JS mirror](malware-settings-js-mirror.md) — settings.js re-checks Config::validate's malware limits; change both, and pair stricter limits with a legacy.rs rewrite
- [CI Success "abandoned"](ci-success-abandoned-jobs.md) — a needed job missing from the run = GitHub Actions incident; `gh run rerun --failed` (~10 min, skips the ~2 h coverage)

## Decisions

- [Adaptive refresh pacer](decisions/cache-adaptive-refresh-pacer.md) — why PR #211 paced by backlog and removed `cache_max_refresh_per_sec`; superseded by per-entry timers
- [Wildcard local records](decisions/wildcard-local-records.md) — why the wildcard layer sits above the cache; two permanent-entry bugs found and fixed in the same PR
- [Exact local records answer NODATA](decisions/local-record-exact-nodata.md) — PR #227: an exact A/AAAA owns the whole name, so split-horizon overrides lose every other type
- [Restart banner is a sticky server flag](decisions/restart-banner-server-flag.md) — PR #236: in-memory `restart_pending`, cleared only by a restart; config diff rejected
- [DNS cookie echo + strict mode](decisions/dns-cookie-strict-mode.md) — #279: cookie on every reply; strict is UDP-only, fast path off, BADCOOKIE + EDE 18; #361: per-window rotation
- [Per-entry refresh timers](decisions/cache-per-entry-refresh-timer.md) — 60 s scan + pacer replaced by one timer per entry; due rule, timer states, one follow-up decision, inbox not channel
- [Pi-hole compat scope](decisions/pihole-compat-scope.md) — serves integrations, not the Pi-hole UI or sync tools; /config, /teleporter, /logs, flush/network stay unserved, and why
- [Conditional pool routing](decisions/conditional-pool-routing.md) — #291: routes are pool fields; no fallback (SERVFAIL); per-group cache view; SQLite table and id-pruning rejected
- [Cache removal by events](decisions/cache-event-driven-removal.md) — eviction/compaction jobs → worker tick + per-entry expiry timers; same rules; ≥1 timer per entry; lossless inbox
- [Release PR flow](decisions/release-pr-flow.md) — releases via a regenerated chore(release) PR; PAT for anything that starts a workflow; docs ride release-created
- [Query-log rollups and disk space](decisions/query-log-rollups-and-disk-space.md) — #311: hourly rollups filled by a job (writer upserts halved throughput), incremental auto-vacuum, `--compact-database`; reads stay exact
- [Roadmap as milestones](decisions/roadmap-as-milestones.md) — #340: ROADMAP.md → GitHub milestones + issues; TLD blocking, NRD, ACME, DDNS, anomaly detection, RFC 7828 dropped, and why
- [Stream transports have their own rate-limit budget](decisions/rate-limit-stream-budget.md) — #355: TCP/DoT/DoH/DoQ buckets apart from UDP, REFUSED not TC=1; BIND exemption rejected (no DoH conn cap)
- [Malware exemptions via groups](decisions/malware-exemptions-via-groups.md) — #356: config exemption lists → DNS Filter allow + per-group switch; one screening gate, cache hits too
- [Rcode response counters](decisions/rcode-response-counters.md) — #363: `ferrousdns_responses_total{rcode}` counted at the handler's exits; per-site counters and a SERVFAIL table rejected
- [bind_address "auto": dual-stack, IPv4 without kernel IPv6](decisions/bind-address-auto-dual-stack.md) — #385 default `[::]`; #386 family follows the address, IP_PKTINFO path, `listen_config` probe; seccomp test harness
- [A disabled group falls back to the default group](decisions/disabled-group-falls-back-to-default.md) — #382: IP/subnet/DoH matches of a disabled group resolve to Protected in the loader's SQL; migration re-enabled old ones; backup carries it
- [Upgrades keep existing behaviour](decisions/upgrades-keep-existing-behaviour.md) — v1.0.0 rule: new behaviour is opt-in; why the Docker DB stays at /data/ferrous-dns.db, import keeps a full restore

## Bugs

- [local_dns_server forwarder was unhardened](bugs/local-dns-forwarder-unhardened.md) — no 0x20, cookie or TXID check on local answers; fixed by #240 (2026-09-23)
- [dashmap Iter holds the shard guard](bugs/cache-eviction-random-branch-deadlock.md) — collect keys into a let-statement before removing (issue #228, fixed 2026-09-19)
- [Settings upstream health 404](bugs/settings-upstream-health-404.md) — `/health/upstreams` 404 only fed the pool editor's ❓ badge; both removed in #297 (e2136494, v0.9.24)
- [Vendored OpenSSL blind spot](bugs/vendored-openssl-blind-spot.md) — webauthn-rs 0.5 linked OpenSSL 3.6.3 that Trivy and cargo audit missed; resolved by #380 (2a351899, 11-09)
- [Backup import skips the restart flag](bugs/backup-import-no-restart-flag.md) — `/config/import` never set `restart_pending`; fixed by #306 (676b0093, 10-23), incl. the DNSSEC-mode normalization
- [Query Log DOMAIN column collapses](bugs/query-log-domain-column-collapse.md) — issue #235: fixed with container queries; widen every threshold when adding a column
- [Mobile layout overflow](bugs/mobile-layout-overflow.md) — admin pages scrolled sideways at 320–960px; fixed by #309 (7537fadf, 10-24); how to audit a layout change
- [Upstream rcode logged as NOERROR](bugs/upstream-rcode-ignored-on-pool-path.md) — caching/failover fixed by #282; query log by #305; RRL/tunneling by #341 (#322); TC=1 slip over TCP by #355 (#339)
- [Blocklist download timeout + list size](bugs/blocklist-download-timeout-and-list-size.md) — issue #248: stall-based timeouts, held list copies, HaGeZi RAM table, paused-clock test gotcha
- [Upstream hostnames never resolved (#250)](bugs/upstream-hostname-startup-only-resolution.md) — system-only lookup looped through ferrous itself; #255 asks local_dns_server first + retries; #307 refreshes IPs at their TTL
- [Cache dead config + L1 hit undercount](bugs/cache-dead-config-and-l1-hit-undercount.md) — all fixed: L1 undercount by #286, wording by #342, the two dead knobs retired by #361 (#320)
- [Cache Time counts coalesced followers](bugs/cache-time-counts-coalesced-followers.md) — followers now count as upstream answers with a `coalesced` marker + Query Log icon; fixed by #308 (115e8524)
- [CNAME chain names kept the trailing dot](bugs/cname-target-cached-under-dotted-name.md) — target shortcut never hit, cloaking never blocked; #354 (975e562e) normalizes, caches the chain, removes the shortcut
- [Backup omits pools and detectors](bugs/backup-snapshot-omits-pools-and-detectors.md) — pools/routes, rate_limit, malware + group-id translation fixed by #306 (10-23); other DNS fields still unmirrored
- [String :style wipes the inline style](bugs/alpine-string-style-replaces-inline-style.md) — Alpine replaces style="" on a string binding; bind objects; 19 elements fixed by #384 (07dcbb78, 11-09)
- [x-show drops inline display](bugs/alpine-xshow-drops-inline-display.md) — Alpine's x-show strips an inline `display:grid`; the pool editor row was redesigned in #297 (v0.9.24); the trap remains
- [Blocked Domains counts adblock rules twice](bugs/blocked-domains-counts-adblock-rules-twice.md) — card was exact + wildcard, so `||domain^` counted 2x (5.12M vs 2.79M); fixed in #297 (e2136494, v0.9.24)
- [Filtered queries logged as SERVFAIL/Upstream](bugs/filtered-query-logged-as-servfail-upstream.md) — non-FQDN/private-PTR refusals logged SERVFAIL/"Upstream"; fixed in #300 (38d257ac, v0.9.24); labels (#326) by #361
- [Eviction prefix sample + fixed batch](bugs/cache-eviction-prefix-sample-fixed-batch.md) — #324 fixed by #360 (776daeda, 11-03): overshoot + headroom, rotating cursor; open: `insert_permanent` pass overlap, `evict_if_full` bias
- [Manual client names can't be cleared](bugs/manual-client-name-cannot-be-cleared.md) — since #343 a blank name changes nothing; pre-migration names (NULL source) still lose to PTR/mDNS
- [Known test flakes](bugs/known-test-flakes.md) — UDP-pool runtime race + TCP reconnect bound fixed by #377 (11-09); hour-boundary rollup, flush at :00, `free_port` AddrInUse open
- [Docker DB path vs the image default](bugs/docker-database-path-ignores-image-default.md) — DB stays at /data/ferrous-dns.db, docs fixed by #371 (d526ad3e, 11-08); env-equals-default skip is a trap
- [Unfiltered window after a start](bugs/cold-start-unfiltered-window.md) — answers before the block index compiles (~0.2 s, HaGeZi Pro); lists re-downloaded each start; #365 (v1.0.0)
- [Backup import overwrites host fields](bugs/backup-import-overwrites-host-fields.md) — fixed by #372 (b7904e7b, 11-08): opt-in `?keep_host_settings=true`; a missing snapshot key keeps the value
- [Two cache hit rates](bugs/cache-hit-rate-two-definitions.md) — /stats + screens use query-log hits ÷ (hits+misses); /cache/metrics + the gauge count lookups; open, unfiled (11-09)
