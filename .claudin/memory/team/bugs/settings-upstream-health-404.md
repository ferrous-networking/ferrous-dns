---
name: settings-upstream-health-404
description: The Settings page calls /health/upstreams but the API serves /upstream/health, so the per-server drill-down 404s on every load
type: project
paths: web/static/settings.js
---

`web/static/settings.js:253` fetches `${API_BASE}/health/upstreams` (still true on 2026-09-23). No such
route exists — `crates/api/src/handlers/upstream.rs` registers
`/upstream/health` and `/upstream/health/detail`, wired in
`crates/api/src/routes.rs:63-64`. Every load of `settings.html` therefore logs
two 404s in the browser console.

**Why it went unnoticed:** the *DNS Upstream Pools* card still renders healthy
servers, because it is populated from a different call. The only visible symptom
is that the per-IP health breakdown promised by the card's own subtitle ("Click a
server to see per-IP health breakdown") never arrives.

Observed on 2026-09-06 against a debug build of v0.9.15 while capturing docs
screenshots. Not fixed there — that PR was documentation only. The fix is a
one-line URL change in `settings.js`; worth confirming which of the two
`/upstream/health*` routes the panel actually wants before changing it.

See [[runtime-verification-recipe]] for how to bring up an instance to reproduce.
