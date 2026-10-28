# REST API Reference

Ferrous DNS exposes a REST API for managing all aspects of the server. The API is served on the same port as the web dashboard (`web_port`, default `8080`).

---

## Base URL

```
http://<server>:8080/ferrous/api/v1
```

The Ferrous API answers at `/ferrous/api/v1` whether or not `pihole_compat` is on. With `pihole_compat = true`, the [Pi-hole v6 API](#pi-hole-v6-compatibility-api) takes `/api`.

---

## Versioning

The `v1` in the base URL is the API's major version.

- **Until 1.0.0**, v1 can still change while its contract is settled.
- **From 1.0.0**, v1 only changes in ways existing clients keep working with: new endpoints, new optional request fields or query parameters, and new response fields. Clients should ignore response fields they do not know.
- **A breaking change** ships as a new major version at `/ferrous/api/v2`. v1 keeps answering for at least one minor release after v2 ships.

The Pi-hole v6 API at `/api` is not versioned by Ferrous DNS: it follows Pi-hole FTL's v6 API. See [Pi-hole Compatibility](features/pihole-compat.md).

### Migrating from `/api` and `/ferrous/api`

Before v0.10.0 the Ferrous API answered at `/api`, or at `/ferrous/api` with `pihole_compat = true`. Both bases are deprecated and will be removed in 2.0. Until then they answer `307 Temporary Redirect` to the same route and query under `/ferrous/api/v1`:

| Old request | Redirected to |
|:------------|:--------------|
| `GET /api/queries?limit=50` (Pi-hole compat off) | `/ferrous/api/v1/queries?limit=50` |
| `POST /ferrous/api/blocklist-sources` (either mode) | `/ferrous/api/v1/blocklist-sources` |

A 307 keeps the method and the body, so clients that follow redirects keep working, such as browsers, Python `requests` and JavaScript `fetch`. `curl` follows them only with `-L`. Update scripts and integrations to the new base anyway. With `pihole_compat = true`, `/api` belongs to the Pi-hole API and is never redirected.

### Changes in v0.10.0

v0.10.0 settles the v1 contract. Besides the new base above, these responses changed:

- **`GET /health` is public and answers JSON.** It used to need a login when authentication was on and answered a plain `OK`. It now answers `{"status": "ok", "version": "…"}`, or `503` with `"status": "unavailable"` while the DNS listener is down. See [Health Check](#health-check).
- **Config saves that fail answer an error status.** `POST /config`, `POST /settings` and `POST /config/reload` used to answer `200` with `success: false` when a valid request could not be carried out. They now answer `409` (no writable config file) or `500` (the save or reload failed), with the same body. See [Update Config](#update-config).

---

## Interactive Documentation (OpenAPI / Scalar)

Both APIs publish an OpenAPI 3.x specification and ship a built-in [Scalar](https://scalar.com) UI for interactive exploration. Scalar is embedded in the binary, so the explorer works without internet access. The endpoints are public — no authentication is required to read the spec or open the UI.

| API | OpenAPI spec | Interactive docs |
|:----|:-------------|:-----------------|
| Ferrous (every mode) | `GET /ferrous/api/v1/openapi.json` | `GET /ferrous/api/v1/docs` |
| Pi-hole v6 (`pihole_compat = true`) | `GET /api/openapi.json` | `GET /api/docs` |

The spec describes every handler, request/response schema, parameter and security scheme (`session_cookie` + `X-Api-Key` for the native API, `X-FTL-SID` for the Pi-hole layer). Each spec names the base it is served under as its server, so Scalar's **Try it** and generated clients call the right URLs. It can be fed into any OpenAPI-aware tool (Postman, openapi-generator, schemathesis, …) to produce clients or contract tests — see [Integrations](integrations.md) for examples.

---

## Authentication

When authentication is enabled (`[auth]` section in config), all API endpoints require either a valid session cookie or an API token — except the public auth endpoints listed below.

### Session Authentication

Authenticate via the login endpoint to receive a session cookie:

```http
POST /ferrous/api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

The server sets a `ferrous_session` cookie on successful login. The cookie is sent automatically with subsequent requests from the dashboard.

### API Token Authentication

For programmatic access, include an API token in the `X-Api-Key` header:

```http
X-Api-Key: your-api-token
```

Create and manage tokens via the [API Token endpoints](#api-tokens) below.

!!! note "Both methods accepted"
    The auth guard accepts either a valid session cookie or an `X-Api-Key` header. You do not need both.

---

## Response Format

All responses are JSON. Successful mutations return:

```json
{
  "success": true,
  "message": "Operation completed successfully"
}
```

Errors return an appropriate HTTP status code with:

```json
{
  "error": "Description of the error"
}
```

Validation failures (a malformed name, URL, comment, CIDR, regex, action, etc.) return `400 Bad Request`. Creating or renaming something to a name that is already taken returns `409 Conflict`, as does deleting a group that still has assigned clients or that an upstream pool routes domains for. Length limits count characters, not bytes.

---

## Health & System

### Health Check

```http
GET /ferrous/api/v1/health
```

Public: no session or API token is needed, even with authentication on, so an uptime monitor or a load balancer can call it. It answers JSON:

```json
{ "status": "ok", "version": "0.10.0" }
```

| Status | `status` | When |
|:-------|:---------|:-----|
| `200 OK` | `ok` | The web server is up and the DNS listener is serving. |
| `503 Service Unavailable` | `unavailable` | The DNS listener is down: its port could not be bound (another resolver holds port 53, for example) or every worker exited. |

The Docker image's health check calls it through [`ferrous-dns --healthcheck`](getting-started/installation.md#health-check).

### System Info

```http
GET /ferrous/api/v1/system/info
```

Returns system information: kernel version, load averages, memory usage.

### Hostname

```http
GET /ferrous/api/v1/hostname
```

Returns the server hostname.

---

## Statistics

### Dashboard

```http
GET /ferrous/api/v1/dashboard?period_hours=24
```

Returns a single aggregated payload for the dashboard view: summary counts, the
query timeline, top blocked domains, top clients and the query-type breakdown.
Use the optional `period_hours` parameter to change the look-back window
(defaults to 24 hours). `malware_detection_enabled` says whether the malware
detectors run, which is the master switch as of the last restart, not a saved
change still waiting for one.

Summary counts, cache stats, DNSSEC stats and the timeline are served from
per-minute rollups, so their windows are minute-aligned: a window includes the
whole minute it starts in. The query log, top-N lists and the query rate read
the raw log and use the exact cutoff.

### Summary Stats

```http
GET /ferrous/api/v1/stats
```

Returns aggregated query statistics: total queries, blocked queries, block rate.

### Query Rate

```http
GET /ferrous/api/v1/stats/rate?unit=second
```

Returns the current query rate. Supports `unit=second` or `unit=minute`.

### Query Timeline

```http
GET /ferrous/api/v1/queries/timeline
```

Returns query volume over time for dashboard graphs.

### Top Blocked Domains

```http
GET /ferrous/api/v1/stats/top_blocked
```

### Top Clients

```http
GET /ferrous/api/v1/stats/top_clients
```

---

## Query Log

### List Queries

```http
GET /ferrous/api/v1/queries?limit=100&offset=0
```

Returns recent DNS queries with filtering support.

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `limit` | integer | Max results (default: 100) |
| `offset` | integer | Pagination offset |
| `protocol` | string | Transport the client used: `udp`, `tcp`, `dot`, `doh` or `doq`. Case-insensitive; any other value returns `400` |

Each entry carries a `protocol` field with the same values in lowercase, or
`null` for internally generated queries and for rows logged before the
transport was recorded.

`coalesced` marks a query's part in [in-flight coalescing](architecture/overview.md#in-flight-coalescing):
`leader` when identical queries that arrived while it was in flight shared its
answer, `follower` when it got such a query's answer with no upstream request of
its own, and `null` otherwise. A follower carries its leader's `cache_hit`,
`upstream_server` and `upstream_pool`, and its own response time.

---

## Configuration

### Get Config

```http
GET /ferrous/api/v1/config
```

Returns the full current configuration including server, DNS, blocking, logging, and database settings.

`restart_required` is `true` while a saved change is waiting for a server restart to take effect — set by `POST /ferrous/api/v1/config` (anything but upstream pools), `POST /ferrous/api/v1/settings`, and the TLS certificate upload/generate endpoints. It is held in memory, so restarting the server resets it; the web UI's restart banner follows it.

### Update Config

```http
POST /ferrous/api/v1/config
```

Partial update — only include the sections you want to change:

```json
{
  "dns": {
    "cache_enabled": true,
    "cache_max_entries": 200000
  },
  "blocking": {
    "enabled": true
  }
}
```

**Server settings** (require restart):

```json
{
  "server": {
    "pihole_compat": true
  }
}
```

**Upstream pools** (hot-applied). `pools` replaces the whole list. A pool with `domains` is a [conditional pool](configuration/dns.md#conditional-forwarding); `groups` and `internal` only apply to one:

```json
{
  "dns": {
    "pools": [
      { "name": "public", "strategy": "parallel", "priority": 1,
        "servers": ["https://cloudflare-dns.com/dns-query"] },
      { "name": "office-a", "strategy": "failover", "priority": 1,
        "servers": ["udp://10.1.0.10:53"],
        "domains": ["corp.example"], "groups": [2], "internal": true }
    ]
  }
}
```

`GET /ferrous/api/v1/config` returns `domains`, `groups` and `internal` on every pool, empty or `false` for a default pool. When a save changes where some name is routed, the DNS cache is cleared.

**Malware detection** (require restart). The master switch and the rebinding keys sit in `dns`; each engine is a nested object with the keys of its `ferrous-dns.toml` section ([reference](configuration/ferrous-dns-toml.md#tunneling-detection)), and any subset of them can be sent:

```json
{
  "dns": {
    "malware_detection_enabled": true,
    "rebinding_protection_enabled": true,
    "rebinding_allowlist": ["router.example.com"],
    "tunneling_detection": { "action": "alert", "client_whitelist": ["10.0.0.50"] },
    "dga_detection": { "confidence_threshold": 0.7 },
    "nxdomain_hijack": { "probes_per_round": 3 },
    "response_ip_filter": {
      "enabled": true,
      "ip_list_urls": ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    }
  }
}
```

`GET /ferrous/api/v1/config` returns all of them, every key of every engine included.

The merged configuration is validated before anything is applied. An invalid value — an unknown `block_mode`, `dnssec_mode` or malware detection `action`, an unparseable server or sinkhole address, a `local_dns_server` that is not an IP address or `IP:port`, a zero interval, timeout or capacity such as `cache_compaction_interval: 0`, a malware detection threshold outside its range such as `confidence_threshold: 1.5`, a whitelist entry that is not an exact domain name or an IP/CIDR, a feed URL without `http://` or `https://`, response IP filtering enabled without a feed URL, a session lifetime whose expiry is past the latest representable date such as `session_ttl_hours: 4294967295`, or pools that cannot route (an invalid domain, `groups` or `internal` without `domains`, no pool without `domains`, a domain routed to two pools for the same clients, a client group that does not exist) — returns **400** with `{ "success": false, "error": "…" }` naming the key, and neither the live server nor the file changes.

A request that is valid but cannot be carried out answers with an error status and the same `{ "success": false, "error": "…" }` body:

| Status | When |
|:-------|:-----|
| `409 Conflict` | There is no writable config file: the server was started without one, or the file's permissions mark it read-only. Nothing was applied. |
| `500 Internal Server Error` | The save was attempted and failed: the file could not be written (on a read-only mount, for example), the client groups could not be read, or the upstream pools could not be applied. If the pools went live but the file could not be written, `error` says so: retry the save, since a restart would revert them. |

The file is rewritten atomically (a synced temp file renamed over it), so a crash mid-save leaves the old or the new file, never a truncated one. The new file keeps the old one's mode, owner and group. When the file cannot be replaced — a Docker single-file bind mount, a directory the server cannot write, or an owner or group the server cannot give the new file — it is rewritten in place instead.

### Reload Config

```http
POST /ferrous/api/v1/config/reload
```

Reloads the configuration from the TOML file without restarting the server. DNS, blocking, and cache settings take effect immediately. Server-level settings (ports, pihole_compat) require a full restart. A file that fails to load, parse or validate answers **500** with `{ "success": false, "error": "…" }`, and the running configuration is kept. A server started without a config file answers **409**.

The file is loaded the way startup loads it: command-line overrides the server was started with (`--dns-port`, `--web-port`, `--bind`, `--database`, `--log-level`) still win over the file. Changed upstream pools are rebuilt and swapped in live, as with `POST /ferrous/api/v1/config`; if that fails, nothing changes. A reload waits for any config save or backup import in progress, so it never interleaves with one. The Pi-hole `POST /api/action/restartdns` runs the same reload.

### Get Settings

```http
GET /ferrous/api/v1/settings
```

Returns DNS-specific settings (non-FQDN blocking, PTR blocking, local domain).

### Update Settings

```http
POST /ferrous/api/v1/settings
```

**Full replace** — unlike `POST /ferrous/api/v1/config` (a partial update), this endpoint overwrites the entire DNS settings form. Any field you omit reverts to its default: an omitted `sinkhole_ipv4` clears a previously-set sinkhole, an omitted `block_mode` resets it to `null_ip`. Send the complete object:

```json
{
  "never_forward_non_fqdn": true,
  "never_forward_reverse_lookups": true,
  "local_domain": "lan",
  "local_dns_server": "192.168.1.1:53",
  "block_mode": "null_ip",
  "block_ttl": 60,
  "sinkhole_ipv4": "192.168.1.2",
  "sinkhole_ipv6": "fd00::2"
}
```

`sinkhole_ipv4` / `sinkhole_ipv6` set a custom block target for `null_ip` mode (empty string = the null address `0.0.0.0` / `::`). A non-empty value that is not a valid address of the matching family is rejected with **400** and `{ "success": false, "error": "Invalid IPv4 sinkhole address: …" }`, and nothing is saved. See [Custom Sinkhole IP](configuration/blocking.md#custom-sinkhole-ip). The same 400 applies to an unknown `block_mode` (`null_ip`, `nxdomain`, `nodata` or `refused`), a `local_dns_server` that is not an IP address or `IP:port`, and a DNS64 prefix that is not a `/96`. A `local_dns_server` given as a bare IP is saved as `IP:53`.

The response carries `restart_required`: `true` when the save changed a setting (these only take effect after a restart), `false` when the form was saved unchanged. A save that cannot be carried out answers `409` or `500` as [`POST /ferrous/api/v1/config`](#update-config) does.

---

## TLS Certificates

Manage the certificate used for the HTTPS web interface.

### TLS Status

```http
GET /ferrous/api/v1/tls/status
```

Returns the current certificate status: whether TLS is enabled, whether the cert
and key files exist, the certificate subject, expiry (`cert_not_after`) and
whether it is currently valid.

### Upload Certificates

```http
POST /ferrous/api/v1/tls/upload
Content-Type: multipart/form-data
```

Uploads a PEM `cert` and `key` pair via multipart form fields.

**Error codes:** `400 Bad Request` (missing or invalid files), `401 Unauthorized`

### Generate Self-Signed

```http
POST /ferrous/api/v1/tls/generate?force=true
```

Generates a self-signed certificate/key pair. Pass `?force=true` to overwrite
existing files.

**Error codes:** `400 Bad Request` (files already exist — use `?force=true`), `401 Unauthorized`

---

## Configuration Backup

Export and import the Ferrous DNS configuration as a JSON snapshot. A backup
holds:

- the server, DNS, blocking, DNS64, logging and auth settings, including the
  upstream pools and their conditional-forwarding routes, rate limiting and the
  Malware Detection settings;
- the client groups, the blocklist sources and the local DNS records.

It holds no secrets (password hash, API tokens, TLS key contents) and nothing
else: clients, managed domains and regex filters, for example, are not in it.

### Export Config

```http
GET /ferrous/api/v1/config/export
```

Returns a backup JSON document as a download (`Content-Disposition: attachment`,
filename `ferrous-backup-YYYY-MM-DD.json`).

### Import Config

```http
POST /ferrous/api/v1/config/import
Content-Type: multipart/form-data
```

Restores configuration from a previously exported backup file uploaded as a
multipart field (`file`). Returns an import summary describing what was applied.

- Groups are created by name; one that already exists is kept. A pool's routes
  and a blocklist source follow each group by name, so a backup from another
  server lands on the right groups even though their ids differ.
- Blocklist sources and local records that already exist are skipped.
- The settings are validated as a whole: if they fail, none are restored and
  `errors` says why.
- A backup taken before pools, rate limiting and the Malware Detection settings
  were exported leaves this server's own values for them.
- Restored settings take effect after a restart. When they differ from the
  running ones, `restart_required` is `true` and the dashboard shows the restart
  banner.

```json
{
  "success": true,
  "restart_required": true,
  "summary": {
    "config_updated": true,
    "groups_imported": 1,
    "groups_skipped": 1,
    "blocklist_sources_imported": 2,
    "blocklist_sources_skipped": 0,
    "local_records_imported": 3,
    "local_records_skipped": 0
  },
  "errors": []
}
```

A **partial import** still answers `200`: the import is not transactional, so what was restored stays applied. `success` is then `false`, and `errors` names each item that was not restored, such as a local record with an invalid address or a blocklist source routed for a group the backup does not have.

**Error codes:** `400 Bad Request` (invalid backup file), `401 Unauthorized`, `500 Internal Server Error` (the client groups could not be read)

---

## Auth Endpoints

### Auth Status

```http
GET /ferrous/api/v1/auth/status
```

Returns whether authentication is enabled and whether a password has been configured. **Public** — no auth required.

```json
{
  "auth_enabled": true,
  "password_configured": true
}
```

### First-Run Setup

```http
POST /ferrous/api/v1/auth/setup
```

Sets the admin password on first run (when no password is configured). **Public** — no auth required.

```json
{
  "password": "your-new-password"
}
```

!!! warning
    This endpoint is only available when `password_hash` is empty. Once a password is set, it returns `403 Forbidden`.

### Login

```http
POST /ferrous/api/v1/auth/login
```

Authenticates with username and password. Returns a session cookie (`ferrous_session`).

```json
{
  "username": "admin",
  "password": "your-password",
  "remember_me": false
}
```

| Field | Type | Default | Description |
|:------|:-----|:--------|:------------|
| `username` | `str` | — | Admin username |
| `password` | `str` | — | Admin password |
| `remember_me` | `bool` | `false` | Extend session lifetime to `remember_me_days` |

### Logout

```http
POST /ferrous/api/v1/auth/logout
```

Invalidates the current session. **Public** — no auth required (clears session if present).

### Change Password

```http
POST /ferrous/api/v1/auth/password
```

Changes the password of the signed-in user and returns `204`. **Protected** — the session cookie names the user, so an API token alone is refused with `401`. A wrong `current_password` returns `401` and changes nothing.

Every other session of that user is revoked, so a device signed in with the old password has to log in again. The session that made the change stays signed in.

```json
{
  "current_password": "old-password",
  "new_password": "new-password"
}
```

### List Sessions

```http
GET /ferrous/api/v1/auth/sessions
```

Returns all active sessions. **Protected**.

### Revoke Session

```http
DELETE /ferrous/api/v1/auth/sessions/{id}
```

Revokes a specific session by ID. **Protected**. Any authenticated caller — any user's session or any API token — can revoke any user's session, including the admin's; there is no ownership or role check.

---

## API Tokens

Named API tokens for programmatic access. Tokens are stored as SHA-256 hashes — the full token is only shown once at creation.

### List Tokens

```http
GET /ferrous/api/v1/api-tokens
```

Returns all tokens. Only the token prefix is shown in the listing.

### Create Token

```http
POST /ferrous/api/v1/api-tokens
```

```json
{
  "name": "Grafana Integration"
}
```

Response includes the full token value — save it immediately:

```json
{
  "id": 1,
  "name": "Grafana Integration",
  "token": "fdns_a1b2c3d4e5f6..."
}
```

### Update Token

```http
PUT /ferrous/api/v1/api-tokens/{id}
```

Update the token name or import a custom key:

```json
{
  "name": "New Name",
  "key": "custom-imported-key"
}
```

!!! tip "Pi-hole migration"
    Use the `key` field to import existing API keys from Pi-hole or other tools.

### Delete Token

```http
DELETE /ferrous/api/v1/api-tokens/{id}
```

---

## User Management

!!! warning "Roles are informational"
    Every user has a `role` (`admin` or `viewer`), stored on the account and its sessions and shown in the UI and API responses. **Nothing enforces it**: a `viewer` can call every protected endpoint, including configuration changes, user management and API tokens. Give accounts only to people you would trust with full access.

### List Users

```http
GET /ferrous/api/v1/users
```

Returns all users. **Protected**.

### Create User

```http
POST /ferrous/api/v1/users
```

```json
{
  "username": "operator",
  "password": "secure-password",
  "role": "viewer"
}
```

| Field | Type | Default | Description |
|:------|:-----|:--------|:------------|
| `username` | `str` | — | 1–64 alphanumeric characters, `-`, `_` or `.` |
| `display_name` | `str` | — | Optional, up to 100 characters |
| `password` | `str` | — | 8–256 characters |
| `role` | `str` | `viewer` | `admin` or `viewer` (informational, see above); any other value is `400` |

A username that is already taken returns `409`. The `[auth.admin]` username is always taken, even before its password is set in the setup wizard.

### Delete User

```http
DELETE /ferrous/api/v1/users/{id}
```

---

## Cache

### Cache Stats

```http
GET /ferrous/api/v1/cache/stats
```

Returns cache hit/miss counts, hit rate, and total entries.

### Cache Metrics

```http
GET /ferrous/api/v1/cache/metrics
```

Returns detailed cache metrics: hits, misses, evictions, insertions, optimistic refreshes, lazy deletions, compactions, expirations, hit rate. `expirations` counts the positive entries their timer removed past their TTL; `compactions` also counts expired negative answers.

### Cache Overview

```http
GET /ferrous/api/v1/cache/overview
```

What the dashboard's **Cache Refreshes** card shows, from one pass over the cache:

```json
{
  "top_refreshed": [{ "domain": "github.com", "type": "A", "refreshes": 12 }],
  "expiring_soon": 37,
  "expiring_window_secs": 60,
  "inserted": 5120,
  "expired": 1830
}
```

- `top_refreshed` — the five entries renewed most since they were stored, most renewed first; entries never renewed are left out. The counts match `refreshes` in the listing below.
- `expiring_soon` — entries whose TTL ends within the next `expiring_window_secs` (60 s, the lead with which renewal starts, so an entry still inside it is not being renewed).
- `inserted` and `expired` — entries stored and entries removed past their TTL since the server started. The cache lives in memory, so both start from zero on every restart.

### List Cache Entries

```http
GET /ferrous/api/v1/cache/entries?limit=25&offset=0&sort=cached_at&order=desc
```

Returns the entries currently held in the positive cache, with filtering, ordering, and pagination.

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `limit` | integer | Max results (default: 25, max: 500) |
| `offset` | integer | Pagination offset |
| `domain` | string | Case-insensitive substring match on the cached domain |
| `type` | string | Record type name, e.g. `A`, `AAAA`, `CNAME` |
| `sort` | string | `hits`, `refreshes`, `cached_at`, `expires_at`, `domain`, or `type` (default: `cached_at`) |
| `order` | string | `asc` or `desc` (default: `desc`) |

The response is `{ "data": [...], "total": 0, "records_total": 0, "limit": 25, "offset": 0 }`, where `total` counts the entries matching the filters and `records_total` counts every entry in the cache. Each item carries `domain`, `type`, `group_id`, `answers`, `canonical_name`, `dnssec_status`, `ttl`, `remaining_ttl`, `cached_at`, `expires_at`, `hits`, `refreshes`, `last_access`, `permanent`, and `stale`. Timestamps are UNIX epoch seconds; `remaining_ttl` and `expires_at` are `null` for permanent entries. `group_id` is `null` for the entries every client shares; a split-horizon answer from a [conditional pool](configuration/dns.md#conditional-forwarding) routed for one client group carries that group's id, and the same name can be listed once per group.

`hits` counts lookups served from the cache, the per-thread L1 copies of hot A/AAAA records included. L1 hands its hits over in batches, at most once per second per thread, so the count can trail by the last second of them.

`refreshes` counts the times the cache renewed the entry from upstream, ahead of expiry or as a serve-stale repair. Like `hits`, it starts over when a new answer replaces the entry.

### Delete Cache Entry

```http
DELETE /ferrous/api/v1/cache/entries?domain=example.com&type=A
```

Removes a single cache entry. Add `group_id` to remove a client group's split-horizon entry (`&group_id=2`); without it, the entry every client shares is removed. Returns `204 No Content` on success, `404` if the entry is not cached, and `400` if the record type is unknown.

---

## Upstream Health

### Health Summary

```http
GET /ferrous/api/v1/upstream/health
```

Returns health status per upstream server (Healthy / Unhealthy).

### Health Detail

```http
GET /ferrous/api/v1/upstream/health/detail
```

Returns detailed health information per upstream: pool name, strategy, latency metrics, failure counts.

---

## Clients

### List Clients

```http
GET /ferrous/api/v1/clients?limit=1000
```

Returns all detected clients with IP, MAC, hostname, group, query count, and last seen.

### Client Stats

```http
GET /ferrous/api/v1/clients/stats
```

Returns per-client query statistics.

### Create Manual Client

```http
POST /ferrous/api/v1/clients
```

```json
{
  "name": "Living Room TV",
  "ip": "192.168.1.50"
}
```

### Update Client

```http
PATCH /ferrous/api/v1/clients/{id}
```

```json
{
  "name": "New Name"
}
```

### Delete Client

```http
DELETE /ferrous/api/v1/clients/{id}
```

### Assign Client to Group

```http
PUT /ferrous/api/v1/clients/{id}/group
```

```json
{
  "group_id": 2
}
```

---

## Client Subnets

Subnets auto-assign clients matching a CIDR range to a group.

### List Subnets

```http
GET /ferrous/api/v1/client-subnets
```

### Create Subnet

```http
POST /ferrous/api/v1/client-subnets
```

```json
{
  "cidr": "192.168.1.0/24",
  "group_id": 2
}
```

The subnet is stored in canonical form: host bits are cleared and IPv6 is lowercased and compressed, so `192.168.1.5/24` is stored as `192.168.1.0/24` and conflicts with an existing `192.168.1.0/24` (`409`).

Subnets stored before canonicalisation are rewritten the same way at startup. If two stored rows name the same network, the older row is kept and the other is deleted, with a `WARN` naming both rows' ids and groups; clients in that subnet then belong to the kept row's group.

### Delete Subnet

```http
DELETE /ferrous/api/v1/client-subnets/{id}
```

---

## Groups

### List Groups

```http
GET /ferrous/api/v1/groups
```

### Create Group

```http
POST /ferrous/api/v1/groups
```

```json
{
  "name": "Kids",
  "comment": "Children's devices",
  "enabled": true
}
```

`enabled` is optional and defaults to `true`; a group created with `"enabled": false` starts disabled.

### Get Group

```http
GET /ferrous/api/v1/groups/{id}
```

### Update Group

```http
PUT /ferrous/api/v1/groups/{id}
```

### Delete Group

```http
DELETE /ferrous/api/v1/groups/{id}
```

Returns `409` if the group still has assigned clients, or if an upstream pool routes domains for it (its `groups` in a [conditional pool](configuration/dns.md#conditional-forwarding)); remove the group from the pool first. Managed domains (including the rules generated for a blocked service), regex filters, blocklist and allowlist memberships, blocked services, Safe Search settings, client subnets and schedule assignments are removed with the group, and the block filter is reloaded so they stop applying immediately; query-log entries keep their data but lose the group attribution.

### Get Group Clients

```http
GET /ferrous/api/v1/groups/{id}/clients
```

---

## Blocklist Sources

### List Sources

```http
GET /ferrous/api/v1/blocklist-sources
```

### Create Source

```http
POST /ferrous/api/v1/blocklist-sources
```

```json
{
  "name": "HaGeZi Pro",
  "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
  "enabled": true
}
```

The new source is downloaded and the block index rebuilt as part of the request,
so it takes effect on the next query.

### Get Source

```http
GET /ferrous/api/v1/blocklist-sources/{id}
```

### Update Source

```http
PUT /ferrous/api/v1/blocklist-sources/{id}
```

### Delete Source

```http
DELETE /ferrous/api/v1/blocklist-sources/{id}
```

### Sync Sources

```http
POST /ferrous/api/v1/blocklist-sources/{id}/sync
```

Refreshes the given source. The compiled index is a single snapshot keyed by a
global source bitset, so one list cannot be re-downloaded on its own: this
rebuilds the index and therefore re-downloads **every** enabled source. The id
records which list the operator asked for and yields `404` when it does not
exist.

Returns `202 Accepted` as soon as the rebuild starts; it then runs in the
background, since refreshing large lists can take minutes.

Every other change, to a source, managed domain, regex filter, service or group,
rebuilds from the lists already downloaded and fetches only a list the server
does not hold yet. This endpoint, the daily sync job and the Pi-hole
`POST /api/action/gravity` download every list again. A list that fails to
download keeps its previous copy in the index, and its `last_synced_at` does not
change; the log line `Failed to fetch blocklist source` gives the reason.

**Error codes:** `404 Not Found`, `409 Conflict` (a sync is already running),
`401 Unauthorized`

---

## Whitelist Sources

### List Sources

```http
GET /ferrous/api/v1/whitelist-sources
```

### Create Source

```http
POST /ferrous/api/v1/whitelist-sources
```

```json
{
  "name": "My Allowlist",
  "url": "https://example.com/allowlist.txt",
  "enabled": true
}
```

### Get / Update / Delete

```http
GET    /ferrous/api/v1/whitelist-sources/{id}
PUT    /ferrous/api/v1/whitelist-sources/{id}
DELETE /ferrous/api/v1/whitelist-sources/{id}
```

Creating, updating or deleting a whitelist source rebuilds the block filter, as blocklist source changes do, so the change applies without waiting for the daily sync. The rebuild re-downloads every enabled list.

---

## Managed Domains

Individual domains added to the blocklist or allowlist via the dashboard.

### List Domains

```http
GET /ferrous/api/v1/managed-domains?limit=100&offset=0
```

### Create Domain

```http
POST /ferrous/api/v1/managed-domains
```

```json
{
  "domain": "ads.example.com",
  "list_type": "block",
  "comment": "Annoying popup ads"
}
```

### Get / Update / Delete

```http
GET    /ferrous/api/v1/managed-domains/{id}
PUT    /ferrous/api/v1/managed-domains/{id}
DELETE /ferrous/api/v1/managed-domains/{id}
```

`PUT` is a partial update: an absent field keeps its value. Send `"comment": null` to clear the comment.

---

## Regex Filters

### List Filters

```http
GET /ferrous/api/v1/regex-filters
```

### Create Filter

```http
POST /ferrous/api/v1/regex-filters
```

```json
{
  "pattern": "^ads\\d+\\.example\\.com$",
  "list_type": "block",
  "enabled": true
}
```

### Get / Update / Delete

```http
GET    /ferrous/api/v1/regex-filters/{id}
PUT    /ferrous/api/v1/regex-filters/{id}
DELETE /ferrous/api/v1/regex-filters/{id}
```

`PUT` is a partial update: an absent field keeps its value. Send `"comment": null` to clear the comment.

---

## Block Filter Stats

```http
GET /ferrous/api/v1/block-filter/stats
```

Returns blocking engine statistics: total domains in blocklist, total in allowlist, filter size.

---

## Blocklist & Allowlist (Compiled)

### Get Active Blocklist

```http
GET /ferrous/api/v1/blocklist
```

Returns the full compiled blocklist currently in memory.

### Get Active Allowlist

```http
GET /ferrous/api/v1/whitelist
```

Returns the full compiled allowlist currently in memory.

---

## Services (1-Click Blocking)

### Service Catalog

```http
GET /ferrous/api/v1/services/catalog
```

Returns all available service categories (built-in + custom).

```http
GET /ferrous/api/v1/services/catalog/{id}
```

Returns a specific service definition with its domain list.

### Blocked Services

```http
GET /ferrous/api/v1/services?group_id=1
```

Returns services currently blocked for a group.

### Block Service

```http
POST /ferrous/api/v1/services
```

```json
{
  "service_id": "facebook",
  "group_id": 1
}
```

### Unblock Service

```http
DELETE /ferrous/api/v1/services/{service_id}/groups/{group_id}
```

---

## Custom Services

Define your own blockable service categories.

### List / Create

```http
GET  /ferrous/api/v1/custom-services
POST /ferrous/api/v1/custom-services
```

```json
{
  "name": "My Custom Tracker",
  "domains": ["tracker1.example.com", "tracker2.example.com"],
  "category": "tracking"
}
```

### Get / Update / Delete

```http
GET    /ferrous/api/v1/custom-services/{id}
PATCH  /ferrous/api/v1/custom-services/{id}
DELETE /ferrous/api/v1/custom-services/{id}
```

---

## Safe Search

### Get Configs

```http
GET /ferrous/api/v1/safe-search/configs
GET /ferrous/api/v1/safe-search/configs/{group_id}
```

### Toggle Safe Search

```http
POST /ferrous/api/v1/safe-search/configs/{group_id}
```

```json
{
  "platform": "google",
  "enabled": true
}
```

### Delete Configs

```http
DELETE /ferrous/api/v1/safe-search/configs/{group_id}
```

---

## Local DNS Records

Static A/AAAA records served directly from cache.

### List Records

```http
GET /ferrous/api/v1/local-records
```

### Create Record

```http
POST /ferrous/api/v1/local-records
```

```json
{
  "hostname": "nas",
  "domain": "home.local",
  "ip": "192.168.1.10",
  "record_type": "A",
  "ttl": 300
}
```

### Update / Delete

```http
PUT    /ferrous/api/v1/local-records/{id}
DELETE /ferrous/api/v1/local-records/{id}
```

---

## Schedule Profiles

Time-based blocking profiles for parental controls.

### List / Create Profiles

```http
GET  /ferrous/api/v1/schedule-profiles
POST /ferrous/api/v1/schedule-profiles
```

```json
{
  "name": "School Hours",
  "description": "Block social media during school"
}
```

### Get / Update / Delete Profile

```http
GET    /ferrous/api/v1/schedule-profiles/{id}
PUT    /ferrous/api/v1/schedule-profiles/{id}
DELETE /ferrous/api/v1/schedule-profiles/{id}
```

### Manage Time Slots

```http
POST   /ferrous/api/v1/schedule-profiles/{id}/slots
DELETE /ferrous/api/v1/schedule-profiles/{id}/slots/{slot_id}
```

```json
{
  "day_of_week": 1,
  "start_time": "08:00",
  "end_time": "15:00"
}
```

### Assign Schedule to Group

```http
GET    /ferrous/api/v1/groups/{id}/schedule
PUT    /ferrous/api/v1/groups/{id}/schedule
DELETE /ferrous/api/v1/groups/{id}/schedule
```

```json
{
  "profile_id": 1
}
```

---

## Pi-hole v6 Compatibility API

When `pihole_compat = true`, the Pi-hole v6 endpoints below are available at
`/api/*`, while the native API stays at `/ferrous/api/v1/*`. The compatibility layer
is **not read-only** — it implements full CRUD for domains, lists, groups and
clients, a blocking toggle, and the Pi-hole action endpoints. Every route answers
with the response shapes and types of Pi-hole's FTL, and request bodies are read
as JSON whatever their `Content-Type`.

With `[auth]` enabled, every endpoint except `/api/auth`, `/api/info/login` and `/api/info/client`
needs the `sid` from `POST /api/auth` in an `X-FTL-SID` header (or a `sid`
header, or `?sid=`); the native `X-Api-Key` header is not read here — send an
API token as the password instead. See [Pi-hole Compatibility > Authentication](features/pihole-compat.md#authentication).

**Auth & session**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth` | Pi-hole v6 login (session-based). Public |
| `GET` | `/api/auth` | Session status; `401` with the session object without a valid session. Public |
| `DELETE` | `/api/auth` | Logout |
| `GET` | `/api/auth/sessions` | Live sessions; `current_session` marks the presented one |
| `DELETE` | `/api/auth/session/{id}` | End the session listed under `id` |
| `GET` | `/api/info/login` | `{"dns": true, "https_port": N}` (`0` on plain HTTP). Public |

**Stats & history**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/stats/summary` | Dashboard summary stats, with `types`, `status` and `replies` counters |
| `GET` | `/api/history` | Query timeline, 145 ten-minute buckets (also at `/api/stats/history`) |
| `GET` | `/api/history/clients` | Per-client series in the same buckets (`N`, default 10) |
| `GET` | `/api/stats/top_domains` | Top allowed domains (`?blocked=true` for blocked); `count` (default 10) |
| `GET` | `/api/stats/top_blocked` | Top blocked domains; `count` |
| `GET` | `/api/stats/top_clients` | Top clients (`?blocked=true` ranks by blocked queries); `count` |
| `GET` | `/api/stats/query_types` | Query count per type |
| `GET` | `/api/stats/upstreams` | Array of answer sources: `blocklist`, `cache`, then each upstream |
| `GET` | `/api/stats/recent_blocked` | Most recently blocked domains; `count` (default 1) |
| `GET` | `/api/stats/database/summary` | Long-term summary; Unix `from` and `until` required |
| `GET` | `/api/stats/database/top_domains` | Long-term top domains; Unix `from` and `until` required |
| `GET` | `/api/stats/database/top_clients` | Long-term top clients; Unix `from` and `until` required |
| `GET` | `/api/stats/database/upstreams` | Long-term upstream usage; Unix `from` and `until` required |
| `GET` | `/api/stats/database/query_types` | Long-term query type counts; Unix `from` and `until` required |

**Queries & search**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/queries` | Query log (filters: `from`, `until`, `domain`, `client_ip`, `client_name`, `upstream`, `type`, `status`, `reply`, `dnssec`, …; paging: `length`, `start`, `cursor`) |
| `GET` | `/api/queries/suggestions` | Filter values (`count`, default 30) |
| `GET` | `/api/search/{domain}` | Domain-list entries, regex filters, blocklists and allowlists that hold the domain (`partial`, `N`) |

**DNS blocking toggle**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/dns/blocking` | `blocking`: `"enabled"` or `"disabled"`; `timer`: seconds left, or `null` |
| `POST` | `/api/dns/blocking` | Set blocking (optional `timer`: flip back after N seconds, fractions accepted) |

**Domains (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/domains` | List all domains |
| `GET` | `/api/domains/{type}` | List by type (`allow`/`deny`) or kind (`exact`/`regex`) |
| `GET` | `/api/domains/{type}/{kind}` | List by type and kind (`exact`/`regex`) |
| `GET` | `/api/domains/{type}/{kind}/{domain}` | Get one domain |
| `POST` | `/api/domains/{type}/{kind}` | Add one domain or several |
| `PUT` | `/api/domains/{type}/{kind}/{domain}` | Replace or create a domain |
| `DELETE` | `/api/domains/{type}/{kind}/{domain}` | Delete a domain |
| `POST` | `/api/domains:batchDelete` | Batch delete (`[{item, type, kind}]`) |

**Lists / adlists (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/lists` | List adlists (optional `?type=allow\|block`) |
| `POST` | `/api/lists?type=allow\|block` | Add one adlist or several |
| `GET` | `/api/lists/{list}` | Lists with this address or id (optional `?type=`) |
| `PUT` | `/api/lists/{list}?type=allow\|block` | Replace or create an adlist |
| `DELETE` | `/api/lists/{list}?type=allow\|block` | Delete an adlist |
| `POST` | `/api/lists:batchDelete` | Batch delete (`[{item, type}]`) |

**Groups (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/groups` | List groups |
| `POST` | `/api/groups` | Add one group or several |
| `GET` | `/api/groups/{name}` | Get a group |
| `PUT` | `/api/groups/{name}` | Replace, create or rename a group |
| `DELETE` | `/api/groups/{name}` | Delete a group |
| `POST` | `/api/groups:batchDelete` | Batch delete (`[{item}]`) |

**Clients (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/clients` | List clients |
| `POST` | `/api/clients` | Add one client or several (by IP or subnet) |
| `GET` | `/api/clients/{client}` | Get a client (by IP or subnet) |
| `GET` | `/api/clients/_suggestions` | Devices the resolver has seen (`count`, default 50) |
| `PUT` | `/api/clients/{client}` | Update or create a client (by IP or subnet) |
| `DELETE` | `/api/clients/{client}` | Delete a client (by IP or subnet) |
| `POST` | `/api/clients:batchDelete` | Batch delete (`[{item}]`) |

**Info**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/info/client` | The caller's address, method and headers. Public |
| `GET` | `/api/info/version` | Version of each component (`core`, `web`, `ftl`, `docker`) |
| `GET` | `/api/info/ftl` | Resolver process info and counts |
| `GET` | `/api/info/system` | Host uptime, memory (kB), processes and load |
| `GET` | `/api/info/host` | Kernel `uname`, device model and DMI identifiers |
| `GET` | `/api/info/sensors` | Temperature sensors (hwmon) |
| `GET` | `/api/info/metrics` | DNS cache counters |
| `GET` | `/api/info/messages` | Diagnosis messages (always empty), also `/count` and `DELETE /{id}` |
| `GET` | `/api/info/database` | Database file and stored query counts |

**Network and DHCP**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/network/gateway` | Default routes with their interface addresses |
| `GET` | `/api/network/routes` | Routing table |
| `GET` | `/api/network/interfaces` | Interfaces with their addresses |
| `GET` | `/api/network/devices` | Devices built from the known clients (`max_devices`, `max_addresses`) |
| `GET` | `/api/dhcp/leases` | Always empty: Ferrous serves no DHCP |

**PADD and endpoint list**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/padd` | One-call summary for PADD (`full`, default true) |
| `GET` | `/api/endpoints` | Every documented route by HTTP method |

**Actions**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/action/gravity` | Reload the blocklists, streaming `text/plain` progress like `pihole -g` |
| `POST` | `/api/action/restartdns` | Reload configuration in-memory |
| `POST` | `/api/action/flush/logs` | Delete every stored query |

See [Pi-hole Compatibility](features/pihole-compat.md) for details, the reply
shapes that changed in v0.9.23, and the [limitations](features/pihole-compat.md#limitations).
