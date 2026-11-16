---
name: runtime-live-ui-session
description: Running a live dashboard session for UI work — shipped config in a scratch dir, rebuild per tweak, dig traffic, rate-limited rows, toasts not dialogs, the UI-wide Playwright audit, per-frame animation checks, Settings pool saves
type: project
---

Part of [[runtime-verification-recipe]], which has the base config, ports and how to stop instances.

**Setup on the shipped config** (2026-11-14):
- Copy `ferrous-dns.toml` into a scratch dir next to a `migrations` symlink. Run `target/debug/ferrous-dns --config ferrous-dns.toml --dns-port 25353 --web-port 8080 --bind 127.0.0.1`. On a dev host, systemd-resolved and Docker already hold port 53.
- **Not from the repo root.** The auth setup and Settings saves rewrite the tracked `ferrous-dns.toml`, and the `lists/` dir created beside the DB is not gitignored.
- **Iterating.** The web assets are `include_str!`'d, so every UI tweak needs a rebuild and a restart. An asset-only debug rebuild takes about 2 s.
- **After a host reboot** the scratchpad is empty, since it is tmpfs. The instance dir, its database, and the start and traffic scripts are gone, and the next start shows the auth setup screen again (seen 2026-11-15).

**Seeding:**
- **Traffic for Query Log and Clients:** loop `dig -b 127.0.0.N` over a list of names. Loopback accepts any 127/8 source, and each source address shows up as its own client. About 5 qps, with about 10% random NXDOMAIN subdomains, stays far under the shipped rate limit (1000 qps per /24, 50 NXDOMAIN/s).
- **Blocking screens:** the shipped config has no blocklist, so they stay empty.
- **Rate-limited rows on the first page:** set `[dns.rate_limit] queries_per_second = 5` and `burst_size = 5` on the verification instance. Then most of 25 concurrent digs from one 127.x source come back `RATE_LIMITED`. The bucket is per /24, so every 127.0.0.x shares it. Fire that burst before the normal names, or the Query Log's 25-row first page holds only burst rows.
- **Clear leftovers before seeding.** A rule an earlier run created, such as a still-live temporary allow, flips the next run's verdicts.
- **Expected console noise:** right after a restart the cache is empty, so the UI's "Remove from cache" logs a 404 in the console.

**Driving the UI:**
- **Outcomes are toasts** since the 2026-11-14 standardization. Read `.toast`, not `page.on('dialog')`. A dialog listener now sees only `confirm()`.
- **Pages with several forms** (DNS Filter has one per tab, all in the DOM): scope selectors to the form, e.g. `form:has(#md-bulk-domains) button[type=submit]` and `button[title="Edit"]:visible`. A bare `form button[type=submit]` resolves to a hidden tab's button and times out.
- **UI-wide change check** (used 2026-11-14 for the standardization round), which runs in about 2 minutes:
  - Drive playwright-core over all 11 pages at 1920, 1440, 1280, 1024, 768 and 390px in light, plus 1920 in dark.
  - Collect `pageerror` and console errors.
  - Flag any element under `main` whose right edge passes `clientWidth` with no `overflow` auto/scroll/hidden ancestor.
  - Save a full-page screenshot per page.
- **Checking an animation:** in the page, sample every row's `getBoundingClientRect().top` on `requestAnimationFrame` for a few seconds while traffic flows. Then, per frame, take the median move of the rows present in both frames. Count one-frame jumps (|move| > 20 px) and still frames. This caught a FLIP flash and transition-start stalls that screenshots and timing logs missed (2026-11-15).

**Saving pools from the Settings UI on the minimal config** (the pool editor is on the **DNS Advanced** tab):
- The first save returns "Restart the server for the changes to take effect". The form sends every `dns` field, and they differ from the stub file.
- Once the file has been written, later pool-only saves report "applied immediately" (seen 2026-10-16).
- To confirm the pool went live, check `GET /ferrous/api/v1/upstream/health/detail` or the `/ferrous/api/v1/config` pools.
