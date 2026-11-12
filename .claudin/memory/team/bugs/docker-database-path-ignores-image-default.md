---
name: docker-database-path-ignores-image-default
description: The Docker image always kept its database at /data/ferrous-dns.db but documented /data/db/ferrous.db. #371 (d526ad3e, 2026-11-08) fixed the docs and kept the path; the entrypoint still skips any env set to its default value, which remains a trap
type: project
paths:
  - docker/entrypoint.sh
  - Dockerfile
  - Dockerfile.release
---

**Symptom (before #371):** On a fresh volume the image wrote its database to `/data/ferrous-dns.db`, and `/data/db/` stayed empty, even though the image set `FERROUS_DATABASE=/data/db/ferrous.db`.

**Where:** `docker/entrypoint.sh` turns an env var into a CLI flag only when its value differs from the default. So the default value never produced `--database`. The bundled `ferrous-dns.toml` won instead, with `[database] path = "ferrous-dns.db"`, which resolves against `WORKDIR /data`. The config is copied into the volume only once, so existing installs keep that relative path.

**Status:** fixed by #371 (`d526ad3e`, merged 2026-11-08, issue #364). The fix documents the real path instead of moving the database:
- Both Dockerfiles no longer set a `FERROUS_DATABASE` default. README, `docker-compose.yml` and the docs now name `/data/ferrous-dns.db`.
- The entrypoint still ignores the old value `/data/db/ferrous.db`. On server start only, it prints a NOTICE to stderr (`entrypoint.sh:70-78`). Any other value still moves the database.
- `/data/db` stays in the image (`Dockerfile:58`, `Dockerfile.release:16`). #371 first removed it, and then a fresh install configured with its database under `/data/db` failed to open it (SQLite code 14). It was restored in review (`e9f3eceb`).

Why the path stayed: [[upgrades-keep-existing-behaviour]].

**Trap that remains:** the same skip applies to `FERROUS_DNS_PORT=53`, `FERROUS_WEB_PORT=8080`, `FERROUS_BIND_ADDRESS=0.0.0.0` and `FERROUS_LOG_LEVEL=info` (`entrypoint.sh:58-82`). Setting one of these to its default cannot override a different value in the config file. #385 (`c2839ba6`, 2026-11-10) kept the `0.0.0.0` skip on purpose when the default became `"auto"`: it dropped `FERROUS_BIND_ADDRESS` from both Dockerfiles and the compose file, and the entrypoint now prints a NOTICE for that value ([[bind-address-auto-dual-stack]]).

**Repro of the trap** (read from the script, not run): put `bind_address = "127.0.0.1"` in the volume's config and run with `-e FERROUS_BIND_ADDRESS=0.0.0.0`. The entrypoint passes no `--bind`, so the server binds 127.0.0.1.
