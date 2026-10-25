---
name: pihole-compat-live-validation
description: How to check Pi-hole compat changes against a live Pi-hole v6 and the real integrations (Homarr, Homepage, Glance, eko, HA hole, PADD), and the setup traps
type: reference
---

FTL mirror structs only catch what their YAML says. For issue #288, comparing against a live Pi-hole caught three things the mirrors missed: the JSON 405 body, `prefsrc`, and `perm_address`.

- **Live diff.**
  - Run `pihole/pihole:latest` with `FTLCONF_webserver_api_password` set and its web port on loopback.
  - Seed it and Ferrous the same way through their own APIs (Pi-hole's `/api`, Ferrous's `/ferrous/api/v1`): lists, a deny domain, clients, and `dig` traffic.
  - Then compare each served route by status code, recursive key set and JSON types. Ignore values and `took`.
  - Live FTL wins over the YAML when they disagree.
- **Integrations.**
  - Run each client in Docker with `network_mode: host` against a Ferrous on the host. They all log in with one API token. Create it on the native API with `POST /ferrous/api/v1/auth/login`, then `POST /ferrous/api/v1/api-tokens {"name", "token"}` (builds before v0.10.0: `/ferrous/api/...` with `pihole_compat = true`). The clients are:
    - Homarr v2.5.2, which runs an onboarding wizard.
    - Homepage, with `HOMEPAGE_ALLOWED_HOSTS`.
    - Glance's `dns-stats` with `service: pihole-v6`.
    - `ekofr/pihole-exporter`.
    - HA's `hole==0.9.2` in `python:3.13-slim`.
    - PADD's `padd.sh --api ... --secret ... --runonce` under `script` to give it a tty.
    - Nebula Sync, as a negative check.
  - Run each one against main and against the branch, on the same database.
- **Traps.**
  - Homarr's internal Next.js binds :3000, so move Homepage (`PORT=3300`).
  - Homarr's wizard keeps its step in page state, so drive it in one browser session.
  - Glance caches widget data, so restart it after switching binaries.
  - PADD rounds `%cpu` to one decimal, so an idle Ferrous shows 0.0%.
