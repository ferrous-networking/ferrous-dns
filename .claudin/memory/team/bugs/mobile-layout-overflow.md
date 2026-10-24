---
name: mobile-layout-overflow
description: Admin UI pages scrolled sideways on phones and tablets (fixed grids, tab bars, unwrapped tables, fixed-width Settings controls); fixed on fix/mobile-layout-narrow-screens (6e26cc83, 2026-10-24); how to check a layout change
type: project
paths: web/static/shared.css, web/static/shared.js, web/static/settings.html, web/static/settings.css, web/static/dns-filter.html, web/static/dns-filter.css, web/static/local-dns-settings.html, web/static/local-dns-settings.css, web/static/clients.html, web/static/groups.html, web/static/dashboard.css
---

**Symptom:** at phone widths the whole page scrolled horizontally on Clients, Settings, DNS
Filter, Groups, Local DNS and Block Services. Clients, DNS Filter and Settings also overflowed at
768–960px, and the dashboard overflowed at 320–375px before its charts had data. On `main` before
the fix, 149 of 270 views overflowed (10 pages, every tab, at 320, 360, 375, 390, 412, 768, 800,
900, 1024 and 1920px).

**Causes:**
- `.tab-bar` was a plain flex row in four page CSS files.
- Fixed `repeat(N,1fr)` grids: the Clients stats, Settings System Status and Backup, and the 3-column
  metric grids.
- Tables had no scroll wrapper.
- Settings rows set a text column beside a 150–220px control.

**Fix (branch `fix/mobile-layout-narrow-screens`, commit `6e26cc83`):**
- **Tab bars.** `shared.css` lets `.tab-bar` scroll at ≤1024px, with no visible scrollbar. At
  ≤768px, `.tab-btn` is nowrap and does not shrink, so phones get one line of tabs. Tablets keep
  two-line labels, so most tabs stay in sight.
- **Tapped tab.** `shared.js` scrolls the tapped tab into view inside a `requestAnimationFrame`.
  The panel has to render first: a page scrollbar that appears narrows the bar.
- **Underline.** dns-filter and local-dns tabs overlap the bar border with `margin-bottom:-1px`,
  and a scroll box clips that overlap. At ≤1024px those two pages draw the border as an inset
  box-shadow instead.
- **Focus ring.** At ≤1024px a focused tab draws its outline inside (`outline-offset:-3px`), since
  the scroll box cut the top edge off. The `shared.js` listener also acts only at ≤1024px.
- **Tables.** Eleven tables sit in `<div class="table-scroll">`, the DNS Filter Test and Backtest
  results included. The box scrolls only at ≤1024px; above that, every table fits. Inside it, the
  dns-filter group dropdown opens in place (`position:static`), because a floating menu was cut
  off on the last rows.
- **Grids.** The Clients stats are `auto-fit`. The Settings cards use `minmax(min(340px,100%),1fr)`;
  with 380 they stacked at 1025px. `.metric-grid` is 3 columns, 2 at ≤520px and 1 at ≤340px, so a
  nine-digit cache count fits its tile.
- **Settings rows.** All 48 rows use the `.setting-row` class (`settings.css`), which wraps; the
  borderless ones add `no-divider`. They used to be inline styles.
- **Dashboard.** An empty chart canvas is capped to its box at ≤560px.

**Checking a layout change:**
- Run the overflow audit at every width above, then again with real-looking data: long domain
  names, nine-digit cache counts, and a DNS Filter Test result. The empty-state audit missed the
  cache tiles and the Test table.
- Compare against `main` box by box (cards, tables, th, tabs, inputs, buttons) at 1920, 1440, 1280,
  1100 and 1025px. All 135 views must match.
- Seed both instances identically, and send no DNS queries before comparing. Client tracking
  reorders the Clients rows, which reads as a layout change.
- Run one pass in a headed browser too. Desktop scrollbars take 15px that headless overlay
  scrollbars do not, and that pass caught the tab-scroll timing bug.

**Status:** fixed 2026-10-24; PR not opened yet.

Related: [[query-log-domain-column-collapse]], [[alpine-xshow-drops-inline-display]] (none of the
changed grids use `x-show`).
