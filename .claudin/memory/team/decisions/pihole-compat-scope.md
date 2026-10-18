---
name: pihole-compat-scope
description: The Pi-hole v6 compat API serves integrations, not the Pi-hole web UI or sync tools; /config*, /teleporter, /logs, /auth/app|totp, flush/network and device delete stay unserved, and why
type: project
scope: api-pihole
impact: rejected
---

**Decision:** the Pi-hole v6 compat layer (`crates/api-pihole`) targets integrations: dashboards, exporters, home automation and scripts. These FTL routes stay deliberately unserved:
- `/config*` and `/teleporter`
- `/logs/{dnsmasq,ftl,webserver}`
- `/auth/app` and `/auth/totp`
- `/action/flush/network` and `/action/flush/arp`
- `DELETE /network/devices/{id}`
- `/history/database*`

Every other FTL route is served with FTL's exact shapes. The decision was approved by Viudes on 2026-10-14 when planning issue #288.

**Why:**
- **Real callers.** A source check of real clients on 2026-10-14 found only Nebula Sync calling an unserved route: `GET/POST /teleporter` and `GET/PATCH /config`. Homarr, Homepage, PADD, Glance, eko/pihole-exporter and HA's `hole` 0.9.2 use only served routes. Everything else on the list is called only by the Pi-hole web UI, which cannot work against Ferrous anyway: it authenticates with the `sid` cookie and `X-FTL-CSRF`, and Ferrous has its own dashboard.
- **Cost per route:**
  - `/teleporter` needs a zip/tar crate plus Pi-hole's `gravity.db` and `pihole.toml` formats.
  - `/config*` needs a mapping from FTL's dotted config tree onto `Config`.
  - `/logs/*` needs a log source that does not exist.
- **Data loss.** Devices are built from the clients table, so `flush/network` or a device delete would delete client group and comment settings.
- **Existing features.** App passwords and 2FA are already managed in the Ferrous dashboard (API tokens act as app passwords), so `/auth/app` and `/auth/totp` would add nothing.

**What changes for a teammate:**
- A "Pi-hole compat" request for one of these routes is out of scope by design. Answer it from the Limitations section of `docs/features/pihole-compat.md`; don't implement it.
- Before adding any compat route, find a real client that calls it.
- Check new routes against a live Pi-hole ([[pihole-compat-live-validation]]) and the FTL mirrors ([[pihole-compat-ftl-mirrors]]).
- Unknown routes answer FTL's JSON `404 not_found`.

**Rejected:**
- **Stubbing these routes with empty success replies.** A sync tool would believe it had synced.
- **Serving `/teleporter` in Ferrous's own backup format.** Clients parse Pi-hole's archive.
- **Rejected for #288:** honouring `until` on `/stats/database/*`, and serving `/history/database*`. Both would need a `period_hours` → `from/until` change across about 6 `QueryLogRepository` methods × 8 implementors, for no known client.

**Evidence:** plan `.claudin/plans/proud-swimming-mccarthy.md`; issue #288; branch `feat/pihole-v6-backlog`, not yet pushed as of 2026-10-14.
