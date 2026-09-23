# Team Memory Index

Shared memories for the ferrous-dns team (one file per fact, with `name`/`description`/`type` frontmatter).

<!-- Add one line per memory: - [Title](file.md) — one-line hook -->

- [Cache refresh maximizes coverage](cache-refresh-maximize-coverage.md) — never cap total refresh throughput with a fixed rate; bound concurrency instead
- [Web TLS Secure-cookie invariant](web-tls-secure-cookie-invariant.md) — the cookie's `Secure` flag follows the live transport, never the config flag
- [DnsResolution wire-data invariant](dns-resolution-wire-data-invariant.md) — no `upstream_wire_data` means every non-A/AAAA answer reaches the client empty
- [Runtime verification recipe](runtime-verification-recipe.md) — minimal standalone config to actually run the binary, plus the admin-username and loopback gotchas
- [Issue #216 blocklist sync](issue-216-blocklist-sync.md) — three defects behind "blocklists not syncing", now fixed; plus why there is no per-source refresh
- [Deadlock tests need a timeout guard](deadlock-tests-need-timeout-guard.md) — run the suspect call on a thread behind `recv_timeout`, so a hang fails CI instead of blocking it
- [`/verify` name collision](verify-skill-name-collision.md) — the Skill tool loads the bundled runtime skill, not this repo's CI gate; run the steps or use `/pre-pr`
- [gh write ops: use REST](gh-write-ops-use-rest.md) — GraphQL reports a phantom rate limit on review/issue creation; `gh api --method POST` works
- [Docs screenshot recipe](docs-screenshot-recipe.md) — how the ten dashboard screenshots were seeded and captured, and the conventions to keep
- [Fuzz workspace is invisible to Dependabot](fuzz-workspace-excluded-from-dependabot.md) — duplicate exact pins in `fuzz/Cargo.toml` break every dependency-group bump
- [Container CVE triage](container-cve-triage.md) — the alpine tag lags its own repo; runtime stages need `apk upgrade`, and the binary never loads the image's libssl

## Decisions

- [Adaptive refresh pacer](decisions/cache-adaptive-refresh-pacer.md) — why PR #211 paces by backlog and removed `cache_max_refresh_per_sec`
- [Wildcard local records](decisions/wildcard-local-records.md) — why the wildcard layer sits above the cache, and two unfiled bugs in exact local records
- [Exact local records answer NODATA](decisions/local-record-exact-nodata.md) — PR #227: an exact A/AAAA owns the whole name, so split-horizon overrides lose every other type
- [Restart banner is a sticky server flag](decisions/restart-banner-server-flag.md) — PR #236: in-memory `restart_pending`, cleared only by a restart; config diff rejected

## Bugs

- [dashmap Iter holds the shard guard](bugs/cache-eviction-random-branch-deadlock.md) — collect keys into a let-statement before removing (issue #228, fixed 2026-09-19)
- [Settings upstream health 404](bugs/settings-upstream-health-404.md) — `settings.js` calls `/health/upstreams`; the API serves `/upstream/health`
- [Vendored OpenSSL blind spot](bugs/vendored-openssl-blind-spot.md) — webauthn-rs statically links OpenSSL 3.6.3 into the binary; Trivy and cargo audit both miss it
- [Backup import skips the restart flag](bugs/backup-import-no-restart-flag.md) — `/config/import` rewrites restart-only settings but never sets `restart_pending` (left out of #234)
- [Query Log DOMAIN column collapses](bugs/query-log-domain-column-collapse.md) — issue #235: fixed with container queries; widen every threshold when adding a column
- [Mobile layout overflow](bugs/mobile-layout-overflow.md) — Clients, Settings, DNS Filter, Groups, Block Services scroll sideways at 390px; unfiled
