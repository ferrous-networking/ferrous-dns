---
name: alpine-floating-element-traps
description: Four Alpine 3.13.5 traps hit in the Query Log (2026-11-14/15) — x-show reveals via setTimeout so $nextTick measures 0, $refs from a detached caller is undefined, an item opening a sibling @click.outside panel must .stop, $nextTick itself runs after a paint (use queueMicrotask)
type: project
paths: web/static/*.js
---

**Symptoms** seen while building the Query Log row-actions menu and Why? popover (branch `feat/query-log-row-actions`, 2026-11-14):
1. In Viudes's browser the menu opened just past its ⋯ button and ran off the right edge. Headless Playwright never reproduced this.
2. Removing a rule from inside the popover threw `Cannot read properties of undefined (reading 'offsetWidth')`.
3. A popover opened from a menu item closed on the same click.

**Causes** (Alpine 3.13.5, `vendor/alpinejs-3.13.5.min.js`):
1. `x-show` reveals an element through `setTimeout(show)`, for click-away compatibility. In a `$nextTick` right after the flag flips, the element is still `display:none`, so `offsetWidth` and `offsetHeight` read 0. The timing varies by browser, which is why headless runs can pass.
2. `$refs` resolves by walking up from the element whose handler is running. A re-render can remove that element, for example an item inside an `x-for`/`x-if` that the new result replaces. After that, `this.$refs.x` in a later `$nextTick` or after an `await` is undefined.
3. `@click.outside` on a panel fires for the very click that opened it. By the time that click bubbles to `document`, the panel is visible.
4. `$nextTick` callbacks run from a `setTimeout`, not a microtask, so the browser can paint a frame between Alpine's DOM update and the callback. A FLIP animation started in `$nextTick` showed every row one row lower for one frame, then snapped back (±46 px, measured per frame on 2026-11-15 in the Query Log live feed).

**Fix pattern** (applied in `web/static/queries.js` and `queries.html`):
1. Keep the element at `visibility: hidden` until it is placed. While `offsetWidth` is 0, retry the placement on `requestAnimationFrame`. Measure against `document.documentElement.clientWidth`/`clientHeight`, since `innerWidth` includes the ~15px scrollbar.
2. Read `this.$refs.x` synchronously at the start of the handler, before any `await` or `$nextTick`, and pass the element along.
3. Put `@click.stop` on any item that opens the other panel.
4. To touch the DOM right after a reactive change and before the next paint, queue a `queueMicrotask` after the assignment: it runs after Alpine's own flush, which is also a microtask.

Closing a fixed menu on every `scroll` also closes it on the scroll that a click (or inertia) triggers right after opening. Let the menu follow its anchor instead, and close it only once the anchor leaves the viewport.

**Status:** all handled in `queries.js` on the branch, still uncommitted on 2026-11-14. The traps apply to any future floating element or `$refs` use in `web/static`.

Related: [[alpine-xshow-drops-inline-display]], [[alpine-string-style-replaces-inline-style]].
