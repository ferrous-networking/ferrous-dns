---
name: settings-upstream-health-404
description: The Settings page called /health/upstreams (no such route; the API serves /upstream/health) only to feed the pool editor's ❓ badge; removed with the badge on fix/web-ui-standardization
type: project
paths: web/static/settings.js
---

`web/static/settings.js` (`loadHealthStatus`) fetched `${API_BASE}/health/upstreams` on load and every 10 s. No such
route exists — `crates/api/src/handlers/upstream.rs` registers
`/upstream/health` and `/upstream/health/detail`, wired in
`crates/api/src/routes.rs:63-64`. Every load of `settings.html` therefore logged
a 404 in the browser console.

**Its only consumer** was the badge next to each server field in the pool editor (DNS Advanced tab):
`getServerHealth(srv)` read the 404'd map, so the badge always showed ❓. The *DNS Upstream Pools*
card and its per-server expansion come from `/upstream/health/detail` and never used this call.

**Status:** on 2026-10-18 Viudes asked to drop the badge as useless. PR #297 (`b4aa3560`, unmerged)
therefore removed the badge, `healthStatus`, `loadHealthStatus` and `getServerHealth` instead of
fixing the URL, and the 404 is gone from the console. Health stays visible in the *DNS Upstream
Pools* card, and now also in the dashboard's Upstream card.

Observed first on 2026-09-06 against a debug build of v0.9.15 while capturing docs
screenshots. See [[runtime-verification-recipe]] for how to bring up an instance to reproduce.
