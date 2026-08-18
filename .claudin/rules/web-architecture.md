---
paths: web/**, crates/cli/src/server/web.rs
---

# Web architecture — admin UI

Vanilla HTML/CSS/JS + Alpine.js, **no build step, no framework, no npm**. Don't introduce one.

## Stack

- **Alpine.js 3.13.5** (CDN) — every page is an Alpine app: `<body x-data="app()" x-init="init()">`, `app()` returns the reactive state object. All rendering is declarative (`x-for`, `x-text`, `x-show`) — no manual DOM templating.
- **Chart.js 4.4.1** (CDN) — dashboard charts only.
- **Tailwind** (CDN) + **Lucide** icons (CDN) — nothing is vendored; `shared.js:9` re-renders Lucide icons after DOM changes.
- Design tokens and layout (sidebar, cards) live in `shared.css` (`:root` / `.dark` CSS vars).

## How it's served

- Assets are **compiled into the binary** with `include_str!` in `crates/cli/src/server/web.rs` — routes at `web.rs:167-216`, the `css_handler!`/`js_handler!` macros at `web.rs:333-356`. There is NO `ServeDir`/static dir at runtime: adding a page requires editing `web.rs` (new `include_str!` + route + handler).
- `/ferrous-config.js` is generated at runtime (`web.rs:245-261`) and injects `window.FERROUS_API_BASE` / `FERROUS_VERSION` — that's how the UI discovers the API base; `shared.js:3` falls back to `/api`.
- Gzip via `CompressionLayer` (`web.rs:215`). No CSP or other security headers are set — if you add any, check CDN usage first (Alpine/Tailwind/Chart.js/Lucide all load from CDNs).

## Auth flow

- Cookie session: server sets `ferrous_session` with `HttpOnly; SameSite=Strict` (`crates/api/src/handlers/auth.rs:23,54`); middleware `crates/api/src/middleware/require_auth.rs` accepts cookie or `X-Api-Key`.
- Login page POSTs `/auth/login` (`login.js`), supports MFA (`/auth/2fa/verify`) and passkeys (WebAuthn base64url helpers in `shared.js:230-293`).
- Every page guards with `await checkAuth()` in `init()` — it probes `/auth/sessions` and redirects to `/login.html` on 401 (`shared.js:89-103`). New pages MUST call it.
- Optional API key in localStorage (`ferrous_api_key`); `apiFetch()` (`shared.js:79-85`) injects the `X-Api-Key` header.
