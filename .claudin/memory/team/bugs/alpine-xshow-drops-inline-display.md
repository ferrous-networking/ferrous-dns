---
name: alpine-xshow-drops-inline-display
description: Alpine's x-show removes the inline display property when it shows an element, so x-show on a style="display:grid" div renders as block (pool editor layout bug)
type: project
paths: web/static/settings.html
---

**Symptom:** in Settings > DNS Advanced, a pool with domains shows "Client groups" and "Internal zone" stacked instead of in two columns.

**Where:** `web/static/settings.html:821`, which has `<div x-show="hasDomains(pool)" style="display:grid;grid-template-columns:1fr 1fr;...">`. It came in with #291.

**Cause:** Alpine 3.13.5's x-show calls `el.style.removeProperty("display")` when it shows an element, including on the first render (see `vendor/alpinejs-3.13.5.min.js`). An inline `display:grid` or `display:flex` on the same element is therefore lost. This is the only element in `web/static` that combines the two.

**Fix pattern:** put `x-show` on a wrapper div and keep the grid on an inner div, or move the grid into a CSS class.

**Repro:** add a domain to a pool and look at the row. Screenshots from 2026-10-16 show it on both `main` and the #293 branch.

**Status:** resolved in PR #297, squash-merged as `e2136494` and shipped in v0.9.24 (2026-10-23). The row was redesigned as Groups stacked above an Internal zone toggle, with `x-show` on a wrapper that has no inline `display`, so the grid is gone. The cause still applies to any future `x-show` + inline `display` element.

**History:** it was out of scope for #293, the group-delete fix, which listed it under "Known follow-ups".
