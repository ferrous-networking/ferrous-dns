---
name: web-tls-secure-cookie-invariant
description: The session cookie's Secure flag must follow the transport actually serving, never the [server.web_tls] enabled config flag
type: feedback
---

`AppState.tls_enabled` must be derived from whether the web TLS material actually loaded, never from the `[server.web_tls] enabled` config flag.

**Why:** `load_server_tls_config` returns `Ok(None)` and the server falls back to plain HTTP when the certificate is missing, while the config flag stays `true`. Reading the flag made every session cookie carry `; Secure` over plain HTTP; browsers on a LAN IP discard such a cookie, so login succeeded, the dashboard flashed once, and the next guarded request 401'd back to the login page. That was issue #214, fixed in PR #215 (2026-09-04).

**How to apply:** in `crates/cli/src/main.rs`, load `web_tls_config` before `build_app_state` and pass `web_tls_config.is_some()`. Any future flag that describes "are we serving HTTPS" belongs to the transport, not the config. Reproducing this class of bug requires a non-loopback bind address — see [[runtime-verification-recipe]].
