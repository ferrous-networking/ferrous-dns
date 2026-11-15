---
name: web-ui-shared-components
description: 2026-11-14 web UI standardization (branch feat/query-log-row-actions) — one component set in shared.css + showToast in shared.js; Viudes's picks (h2 24px titles, 24px cards, .table/.table-dense, pill badges, switches, blue Save, toasts) and the options he rejected
type: project
scope: web UI (web/static)
impact: structural
---

**Decision:** Every page uses one set of components defined once in `web/static/shared.css`: `.page-header`/`.page-title`, `.card` (24px padding), `.card-title` (18px), `.btn-*`, `.input`, `.switch`, `.badge` + colour variants, `.table` and `.table-dense`, `.notice`, `.pagination`, `.filter-bar`, `--gap`. Action outcomes go through `showToast()` in `shared.js`. Page CSS keeps only what is page-specific. Viudes chose each rule on 2026-11-14 in two decision rounds after a three-agent audit. Until then every page carried its own copy: 7 `.btn`, 6 `.table`, 6 `.badge`, 3 tab bars, about 90 `alert()`/`confirm()` calls and about 200 hardcoded hex colours.

**Why:** Those copies had drifted, and the drift caused real bugs:
- Settings' `btn-danger` had no CSS.
- Block Services used an undefined `--accent-color`.
- DNSSEC loaded `queries.css` to borrow its styles.
- Light-only notice colours ignored the dark theme.

**What changes for a teammate:**
- Build new UI from the shared classes.
- Don't add a per-page copy of a shared rule, or an inline `padding:24px`, `font-size` or `#hex` colour that a token covers.
- Use `alert()` for nothing. Keep `confirm()` only for destructive actions.
- Lists you manage use `.table`; logs (Query Log, DNSSEC, Cache Control) use `.table-dense`.
- Every on/off control is a `button.switch` with `role="switch"`.
- Save/Add is `btn-primary` (blue). Green means status, never an action.
- A spacing tweak asked for one page goes in `shared.css` for all of them.
- Stat tiles use `.icon-stat` (big `--tone` icon beside label, value and caption): Dashboard Cache Performance, DNSSEC, Settings → Cache. Only the Dashboard's top row keeps its own tinted `.tone-tile`. Numbers are left-aligned under the icon, never centred.
- A list that refreshes keys its `x-for` on a stable id. The Query Log used `query.id||Math.random()` while `/queries` sent no `id`, so every live poll rebuilt all rows; `/queries` now returns `id`, and the live feed's FLIP animation depends on it.

**Rejected:**
- h1 28px page titles: 6 pages had them. Viudes picked h2 24px.
- Compact 16px cards on the log pages, or 16px everywhere.
- A single table style: either all dense or all roomy.
- Square 4px-radius badges.
- Clickable "Enabled" badges in tables.
- A green Save.
- 20px card titles.
- Keeping `alert()`, or standardizing only the inline boxes.
- Centred stat numbers: tried on 2026-11-14, Viudes put them back under the icon.
- Stat cards on Clients: removed, since Groups and DNS Filter have none.

**Evidence:** session of 2026-11-14 on `feat/query-log-row-actions`, uncommitted then. Four per-page agents worked from a written spec. A Playwright audit over 11 pages × 6 widths × both themes came back clean. `.claudin/rules/web.md` did not describe this standard yet.
