---
name: alpine-string-style-replaces-inline-style
description: A string `:style` binding replaces the element's whole style attribute in Alpine 3.13.5, wiping a static style="" on the same element; use object syntax, which merges
type: project
paths: web/static/*.html
---

**Symptom:** on Cache Control, Query Log and DNSSEC, Previous/Next rendered as bare text, with no border or padding. Settings' cache eviction cards had no padding and square corners. Groups' disabled trash icon was 24px instead of 16px. The Query Log SOURCE badge lost its ellipsis. Settings' token and user buttons, and the user role and source badges, lost padding, size or shape.

**Cause:** for a string value, Alpine 3.13.5 calls `setAttribute('style', value)`, which replaces the static `style=""` the element was written with. An empty string clears it. An object value goes through `setStylesFromObject`, which sets each property and restores the previous values when the binding changes. Measured in the browser: `style="opacity:0.5;cursor:not-allowed"`, `border=0px pad=0px`.

**Fix pattern:**
- Next to a static `style`, always bind an object: `:style="cond ? {opacity: 0.5, cursor: 'not-allowed'} : {}"`.
- A string `:style` is fine only on an element with no static `style`. The Settings upstream rows build the whole style in the string, for example.
- To find offenders, scan for tags that carry both `style="` and a `:style` whose value is not an object. 19 elements across 5 pages were found that way on 2026-11-09.

**Status:** all 19 were converted to object syntax by PR #384 (#362), squash-merged as `07dcbb78` on 2026-11-09. A live style diff, main × branch, confirmed the fix. `web/` has no test harness, so CI does not guard this. Re-run the scan after adding any `:style`.

Related: [[alpine-xshow-drops-inline-display]], the same class of Alpine trap for `display`.
