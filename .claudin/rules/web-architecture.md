---
paths: web/**, crates/cli/src/server/web.rs
---

# Web architecture — admin UI

Vanilla HTML/CSS/JS + Alpine.js, **no build step, no framework, no npm**. Don't introduce one.

## Stack

- **Alpine.js 3.13.5** — every page is an Alpine app: `<body x-data="app()" x-init="init()">`, `app()` returns the reactive state object. All rendering is declarative (`x-for`, `x-text`, `x-show`) — no manual DOM templating.
- **Chart.js 4.4.1** — dashboard charts only.
- **Lucide 0.469.0** icons — `shared.js:9` re-renders Lucide icons after DOM changes.
- **Tailwind Preflight only** — the CSS reset, loaded first in `<head>`. No page uses a Tailwind utility class and there is no Tailwind compiler, so utility classes do nothing; style with `shared.css` tokens. **Inter** is the UI font.
- **Everything third-party is vendored** in `web/static/vendor/` (version in the file name; source, SHA-256 and licence in its `README.md`) and served from the binary. Never load a script, stylesheet, font or image from a CDN or other external host: the UI must work without internet access (#271), and `crates/cli/tests/web_assets_local_test.rs` fails CI when a page or stylesheet does.
- Design tokens and layout (sidebar, cards) live in `shared.css` (`:root` / `.dark` CSS vars).

## How it's served

- Assets are **compiled into the binary** in `crates/cli/src/server/web.rs`: our own files via the `static_files!` table (`web.rs:247-285`, one `url => (file, content type)` row each, `include_str!`). There is NO `ServeDir`/static dir at runtime: adding a page means adding its rows there.
- Vendored files go through one route, `/static/vendor/{*file}`, backed by the `VENDOR_FILES` table (`web.rs:183`, `include_bytes!`) and served with `Cache-Control: immutable`. That is why an upgrade must be a **new versioned file name**, never an in-place replacement. A unit test fails if the table and the directory disagree.
- `/api/docs` (Scalar) renders `web/static/api-docs.html` through `utoipa-scalar`'s `custom_html` (`web.rs:128`); it loads the vendored Scalar build with `withDefaultFonts: false`, which keeps it off `fonts.scalar.com`.
- `/ferrous-config.js` is generated at runtime (`web.rs:313`) and injects `window.FERROUS_API_BASE` / `FERROUS_VERSION` — that's how the UI discovers the API base; `shared.js:3` falls back to `/api`.
- Gzip via `CompressionLayer` (`web.rs:287`). No CSP or other security headers are set. Everything is same-origin now, but Alpine's standard build evaluates expressions with `new Function`, so a CSP needs `'unsafe-eval'` or a switch to Alpine's CSP build.

## Auth flow

- Cookie session: server sets `ferrous_session` with `HttpOnly; SameSite=Strict` (`crates/api/src/handlers/auth.rs:23,54`); middleware `crates/api/src/middleware/require_auth.rs` accepts cookie or `X-Api-Key`.
- Login page POSTs `/auth/login` (`login.js`), supports MFA (`/auth/2fa/verify`) and passkeys (WebAuthn base64url helpers in `shared.js:230-293`).
- Every page guards with `await checkAuth()` in `init()` — it probes `/auth/sessions` and redirects to `/login.html` on 401 (`shared.js:89-103`). New pages MUST call it.
- Optional API key in localStorage (`ferrous_api_key`); `apiFetch()` (`shared.js:79-85`) injects the `X-Api-Key` header.
