---
name: mobile-layout-overflow
description: Five admin UI pages scroll sideways on phones (and two on tablets) — fixed grids, tab bars and tables with no scroll wrapper; found 2026-09-23, unfiled
type: project
paths: web/static/clients.html, web/static/clients.css, web/static/settings.html, web/static/settings.css, web/static/dns-filter.css, web/static/groups.css, web/static/block-services.css
---

**Symptom:** at 390px wide the whole page scrolls horizontally on five pages; at 768px
the Clients and Settings pages already do. Everything from 1024px up is clean, and
Dashboard, DNSSEC, Local DNS, Cache Control and Login are fine on phones too.

**Where:**
- Clients — the stat grid is `repeat(4,1fr)` with no breakpoint (`clients.html:118`), and
  the table (`clients.css:100`) has no `overflow-x:auto` wrapper; Actions is cut at 768px.
- Settings — `.tab-bar` (`settings.css:64`) overflows ("Backup" cut at 768px); the
  2-column System Status / Performance grid (`settings.html:134`) cuts the right card.
- DNS Filter — `.tab-bar` (`dns-filter.css:121`) and the blocklist-source table overflow.
- Groups — the table (`groups.css:133`, `groups.html:139`) overflows and the Comment
  column wraps one word per line.
- Block Services — `.tab-bar` (`block-services.css:69`): the "Schedule" tab goes off-screen.

**Repro:** open each page at a 390x844 viewport and check
`document.documentElement.scrollWidth > clientWidth` (overflow was 44–411px per page).

**Status:** found 2026-09-23 during the issue #235 layout audit; no issue filed and not
fixed — it is unrelated to #235 and was proposed as a separate mobile-responsiveness PR.
Related: [[query-log-domain-column-collapse]].
