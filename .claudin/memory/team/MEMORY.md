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
- [Malware settings have a JS mirror](malware-settings-js-mirror.md) — settings.js re-checks Config::validate's malware limits; change both, and pair stricter limits with a legacy.rs rewrite

## Decisions

- [Adaptive refresh pacer](decisions/cache-adaptive-refresh-pacer.md) — why PR #211 paced by backlog and removed `cache_max_refresh_per_sec`; superseded by per-entry timers
- [Wildcard local records](decisions/wildcard-local-records.md) — why the wildcard layer sits above the cache, and two unfiled bugs in exact local records
- [Exact local records answer NODATA](decisions/local-record-exact-nodata.md) — PR #227: an exact A/AAAA owns the whole name, so split-horizon overrides lose every other type
- [Restart banner is a sticky server flag](decisions/restart-banner-server-flag.md) — PR #236: in-memory `restart_pending`, cleared only by a restart; config diff rejected
- [DNS cookie echo + strict mode](decisions/dns-cookie-strict-mode.md) — #279: cookie on every reply; strict is UDP-only, fast path off, BADCOOKIE + EDE 18
- [Per-entry refresh timers](decisions/cache-per-entry-refresh-timer.md) — 60 s scan + pacer replaced by one timer per entry; due rule, timer states, one follow-up decision, inbox not channel
- [Pi-hole compat scope](decisions/pihole-compat-scope.md) — serves integrations, not the Pi-hole UI or sync tools; /config, /teleporter, /logs, flush/network stay unserved, and why
- [Conditional pool routing](decisions/conditional-pool-routing.md) — #291: routes are pool fields; no fallback (SERVFAIL); per-group cache view; SQLite table and id-pruning rejected
- [Cache removal by events](decisions/cache-event-driven-removal.md) — eviction/compaction jobs → worker tick + per-entry expiry timers; same rules; ≥1 timer per entry; lossless inbox

## Bugs

- [local_dns_server forwarder was unhardened](bugs/local-dns-forwarder-unhardened.md) — no 0x20, cookie or TXID check on local answers; fixed by #240 (2026-09-23)
- [dashmap Iter holds the shard guard](bugs/cache-eviction-random-branch-deadlock.md) — collect keys into a let-statement before removing (issue #228, fixed 2026-09-19)
- [Settings upstream health 404](bugs/settings-upstream-health-404.md) — `/health/upstreams` 404 only fed the pool editor's ❓ badge; both removed in PR #297 (unmerged)
- [Vendored OpenSSL blind spot](bugs/vendored-openssl-blind-spot.md) — webauthn-rs statically links OpenSSL 3.6.3 into the binary; Trivy and cargo audit both miss it
- [Backup import skips the restart flag](bugs/backup-import-no-restart-flag.md) — `/config/import` rewrites restart-only settings but never sets `restart_pending` (left out of #234)
- [Query Log DOMAIN column collapses](bugs/query-log-domain-column-collapse.md) — issue #235: fixed with container queries; widen every threshold when adding a column
- [Mobile layout overflow](bugs/mobile-layout-overflow.md) — Clients, Settings, DNS Filter, Groups, Block Services scroll sideways at 390px; unfiled
- [Upstream rcode logged as NOERROR](bugs/upstream-rcode-ignored-on-pool-path.md) — caching/failover fixed by #282 (10-12); query log still says NOERROR for upstream NXDOMAIN; RRL coupling
- [Blocklist download timeout + list size](bugs/blocklist-download-timeout-and-list-size.md) — issue #248: stall-based timeouts, held list copies, HaGeZi RAM table, paused-clock test gotcha
- [Upstream hostnames never resolved (#250)](bugs/upstream-hostname-startup-only-resolution.md) — system-only lookup looped through ferrous itself; #255 asks local_dns_server first + retries; IP refresh still open
- [Cache dead config + L1 hit undercount](bugs/cache-dead-config-and-l1-hit-undercount.md) — two knobs still unused; L1 undercount fixed in #286, but the tooltip/api.md/doc comments still deny it
- [Cache Time counts coalesced followers](bugs/cache-time-counts-coalesced-followers.md) — in-flight followers logged as cache hits with their upstream wait; real hits are ~1.5 µs; unfiled
- [CNAME target cached under dotted name](bugs/cname-target-cached-under-dotted-name.md) — chain target stored as `name.` (trailing dot), never matched by a lookup; the shortcut never hits; unfiled
- [Backup omits pools and detectors](bugs/backup-snapshot-omits-pools-and-detectors.md) — snapshot lacks pools/routes, rate_limit, malware; groups re-import with new ids; unfiled
- [x-show drops inline display](bugs/alpine-xshow-drops-inline-display.md) — Alpine's x-show strips an inline `display:grid`; the pool editor row was redesigned in PR #297 (unmerged); the trap remains
- [Blocked Domains counts adblock rules twice](bugs/blocked-domains-counts-adblock-rules-twice.md) — card was exact + wildcard, so `||domain^` counted 2x (5.12M vs 2.79M); fixed in PR #297 (37804564), unmerged
- [Filtered queries logged as SERVFAIL/Upstream](bugs/filtered-query-logged-as-servfail-upstream.md) — non-FQDN/private-PTR refusals answer 0.0.0.0 + EDE 15 but log SERVFAIL, shown as "Upstream"; fixed in PR #300 (unmerged)
- [Eviction prefix sample + fixed batch](bugs/cache-eviction-prefix-sample-fixed-batch.md) — evict_by_strategy never scores tail shards; batch/pass can be outpaced; kept by "same rules" 10-16
