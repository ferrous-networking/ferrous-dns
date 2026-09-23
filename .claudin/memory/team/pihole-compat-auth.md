---
name: pihole-compat-auth
description: Before changing authentication in the Pi-hole compatible API, read commit 81c1b7b on main first
type: reference
paths: crates/api-pihole/src/middleware.rs, crates/api-pihole/src/handlers/auth.rs, crates/api-pihole/src/routes.rs, crates/api-pihole/src/state.rs
---

Before changing authentication in the Pi-hole compatible API (`crates/api-pihole`),
read commit `81c1b7b` on `main` together with `crates/api-pihole/tests/auth_tests.rs`.
The reasoning behind the current design is there.
