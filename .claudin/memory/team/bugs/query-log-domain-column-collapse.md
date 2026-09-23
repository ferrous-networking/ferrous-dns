---
name: query-log-domain-column-collapse
description: Issue #235 — the Query Log DOMAIN column shrank to 0px on 1025–1306px-wide windows because column breakpoints ignored the 260px sidebar; fixed with container queries, and the rule for adding a column
type: project
paths: web/static/queries.css, web/static/queries.html, web/static/cache-control.css, web/static/cache-control.html
---

**Symptom:** on laptop-sized windows at 100% zoom the Query Log's DOMAIN column
disappears — the "DOMAIN" header overprints "TYPE" and only the record type is visible
(issue #235, reported 2026-09-22). Zooming the browser out to 80% "fixes" it.

**Where:** `web/static/queries.css` — `table-layout: fixed` with eight fixed-width columns
summing 964px (TIME 120, TYPE 70, PROTOCOL 104, CLIENT 130, SOURCE 200, ANSWER 150,
RESPONSE TIME 110, ACTION 80). DOMAIN is the only flexible column and gets the remainder.
On desktop (≥1025px) the table has `viewport − 342px` (sidebar 260 + `main` padding 48 +
card padding/border 34), so **DOMAIN = viewport − 1306px**, while the column-hiding
`@media` breakpoints (1100/900/820/700/640) compare against the whole viewport.
Crept in with PR #191 (ANSWER, +110px) and PR #205 (PROTOCOL, +104px, shipped in v0.9.13):
at 1280px DOMAIN went 188 → 78 → 0px.

**Repro:** measured on 2026-09-23 against a debug build — 1280x800: 0px plus horizontal
scroll; 1366x768: 60px (one letter); 1440: 134px; 1100 and 1025: 0px.

**Status:** fixed on 2026-09-23 on branch `fix/query-log-domain-column` (commit
4111b78, PR #237 opened the same day). Both the Query Log and the Cache Control table (a copy of
the same pattern) now hide columns with container queries on `.table-card`
(`container-type: inline-size`) instead of viewport `@media` rules. Each threshold is the
visible fixed widths + 220px, the agreed DOMAIN floor. Query Log: RT below 1184, ANSWER
below 1074, TYPE+PROTOCOL below 924, ACTION below 750, phone rules below 670. Cache
Control: HIT below 830, ANSWER below 760, TYPE below 610, phone rules below 560 (the
table's `min-width`), ACTION below 540. The accepted cost is RESPONSE TIME hiding at
1440 and TYPE/PROTOCOL at 1092–1265. There is no automated test because `web/` has no
harness; the PR carries a before/after width table instead.

**When adding a column** to either table, raise every threshold below it by the new
column's width, or DOMAIN loses its 220px floor again. That is how #191 and #205
caused this bug.
Related: [[mobile-layout-overflow]].
