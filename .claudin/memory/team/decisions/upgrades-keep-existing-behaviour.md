---
name: upgrades-keep-existing-behaviour
description: v1.0.0 rule (2026-11-05) — an upgrade never changes what an existing install does unless the user opts in; why the Docker database stays at /data/ferrous-dns.db and keep_host_settings is off by default
type: project
scope: docker, config, backup/import
impact: functional
---

**Decision:** an upgrade must not change what an existing install does unless the user opts in. New behaviour comes as a new config key or an import option, and its default is the old behaviour. Viudes set this rule for the v1.0.0 follow-ups on 2026-11-05, and it shaped #364 and #368.

**Why:** installs upgrade by pulling a new image over a volume that already holds their config and database. The image copies the bundled config into the volume only once (`docker/entrypoint.sh`), so whatever a past version wrote there stays in force. A "fix" that moves a path or changes what a restore copies would break those installs silently on the next pull: an empty database, or a server bound to another host's address. README and `docker-compose.yml` had also told users to set `FERROUS_DATABASE=/data/db/ferrous.db` explicitly, so those installs would have been moved too.

**What changes for a teammate:**
- Ship new behaviour behind a key or option whose default is the old behaviour. `bind_address = "auto"` (#385, `c2839ba6`, 2026-11-10) keeps `"0.0.0.0"` IPv4-only for this reason: configs that name it don't change. Its one exception, promised publicly in #375, is a config with no `bind_address` at all ([[bind-address-auto-dual-stack]]).
- Don't "fix" the Docker database path to `/data/db/ferrous.db`. The entrypoint ignores that old value on purpose and prints a NOTICE. Any other value still moves the database. Keep `/data/db` in the image as well ([[docker-database-path-ignores-image-default]]).
- On backup import, `?keep_host_settings=true` (the Settings checkbox) is off by default, so a plain import is still a full restore.
- A new snapshot field must read a missing key as "keep the target's value". `web_bind_address` shows how ([[backup-import-overwrites-host-fields]]).

**Rejected:**
- Honouring `FERROUS_DATABASE=/data/db/ferrous.db`, or moving the file there: every install that followed the README or the compose file would start on an empty database. The docs were changed to match the real path instead.
- Keeping host settings by default: that would change what a restore does for everyone who restores onto the same host.

**Evidence:** plan `.claudin/plans/virtual-zooming-shore.md` (Context and Agreed Decisions). PRs #371 (`d526ad3e`) and #372 (`b7904e7b`), both merged 2026-11-08. Review fixes `e9f3eceb` (`/data/db` restored) and `36e1ecd1`/`367b9108` (a missing key keeps the value).
