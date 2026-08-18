---
paths: web/**
---

# Web conventions — web/static

## Page structure

- One page = one triple `page.html` + `page.css` + `page.js`, all loading `shared.css`/`shared.js`. To add a page you also register it in `crates/cli/src/server/web.rs` (assets are `include_str!`'d — see the web-architecture rule).
- Each page's JS defines a single `app()` returning the Alpine state object; `<body x-data="app()" x-init="init()">`. Keep all state on that object; `init()` starts with `await checkAuth()` and then loads data.
- Page-specific styles go in the page's own CSS; use the shared design tokens (`var(--...)`, `.card`, `.status-box`) from `shared.css` instead of hardcoding colors/sizes.

## API calls

- Use `apiFetch()` from `shared.js` when the endpoint accepts the API key; plain `fetch(\`${API_BASE}/...\`)` otherwise (cookie session covers it). Canonical pattern (`clients.js:38-45`): `const res = await fetch(...); if (res.ok) this.items = await res.json();` inside try/catch.
- Never hardcode the base URL — always `${API_BASE}`.

## Rendering & safety

- Render with `x-text` (auto-escapes). `x-html` only with `escapeHtml()` — see the one allowed example in `queries.html:202` + `queries.js:157-161`. Never `innerHTML` with server/user data.
- Tables/lists: `<template x-for>` (see `clients.html:195-246`). Forms are inline `x-show` panels, not modals; errors surface via `alert()` or inline messages — match the page you're editing.
- After mutating the DOM outside Alpine's rendering, call the Lucide refresh helper so icons render.

## Don't

- Don't add a bundler, npm, framework, or vendored libs — CDN + Alpine is the architecture.
- Don't add a second state object or global mutable variables outside `app()`.
- Don't bypass `checkAuth()` / `apiFetch()` with hand-rolled auth logic.
