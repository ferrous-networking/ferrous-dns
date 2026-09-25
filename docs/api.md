# REST API Reference

Ferrous DNS exposes a REST API for managing all aspects of the server. The API is served on the same port as the web dashboard (`web_port`, default `8080`).

---

## Base URL

| Mode | Base URL |
|:-----|:---------|
| Normal | `http://<server>:8080/api` |
| Pi-hole compat | `http://<server>:8080/ferrous/api` |

When `pihole_compat = true`, the Ferrous API moves to `/ferrous/api/*` and the Pi-hole v6 API occupies `/api/*`.

---

## Interactive Documentation (OpenAPI / Scalar)

Both APIs publish an OpenAPI 3.x specification and ship a built-in [Scalar](https://scalar.com) UI for interactive exploration. The endpoints are public — no authentication is required to read the spec or open the UI.

| Mode | OpenAPI spec | Interactive docs |
|:-----|:-------------|:-----------------|
| Normal | `GET /api/openapi.json` | `GET /api/docs` |
| Pi-hole compat (native API) | `GET /ferrous/api/openapi.json` | `GET /ferrous/api/docs` |
| Pi-hole compat (Pi-hole API) | `GET /api/openapi.json` | `GET /api/docs` |

The spec describes every handler, request/response schema, parameter and security scheme (`session_cookie` + `X-Api-Key` for the native API, `X-FTL-SID` for the Pi-hole layer). It can be fed into any OpenAPI-aware tool (Postman, openapi-generator, schemathesis, …) to produce clients or contract tests — see [Integrations](integrations.md) for examples.

---

## Authentication

When authentication is enabled (`[auth]` section in config), all API endpoints require either a valid session cookie or an API token — except the public auth endpoints listed below.

### Session Authentication

Authenticate via the login endpoint to receive a session cookie:

```http
POST /api/auth/login
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

Validation failures (a malformed name, URL, comment, CIDR, regex, action, etc.) return `400 Bad Request`. Creating or renaming something to a name that is already taken returns `409 Conflict`, as does deleting a group that still has assigned clients. Length limits count characters, not bytes.

---

## Health & System

### Health Check

```http
GET /api/health
```

Returns server health status.

### System Info

```http
GET /api/system/info
```

Returns system information: kernel version, load averages, memory usage.

### Hostname

```http
GET /api/hostname
```

Returns the server hostname.

---

## Statistics

### Dashboard

```http
GET /api/dashboard?period_hours=24
```

Returns a single aggregated payload for the dashboard view: summary counts, the
query timeline, top blocked domains, top clients and the query-type breakdown.
Use the optional `period_hours` parameter to change the look-back window
(defaults to 24 hours).

Summary counts, cache stats, DNSSEC stats and the timeline are served from
per-minute rollups, so their windows are minute-aligned: a window includes the
whole minute it starts in. The query log, top-N lists and the query rate read
the raw log and use the exact cutoff.

### Summary Stats

```http
GET /api/stats
```

Returns aggregated query statistics: total queries, blocked queries, block rate.

### Query Rate

```http
GET /api/stats/rate?unit=second
```

Returns the current query rate. Supports `unit=second` or `unit=minute`.

### Query Timeline

```http
GET /api/queries/timeline
```

Returns query volume over time for dashboard graphs.

### Top Blocked Domains

```http
GET /api/stats/top_blocked
```

### Top Clients

```http
GET /api/stats/top_clients
```

---

## Query Log

### List Queries

```http
GET /api/queries?limit=100&offset=0
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

---

## Configuration

### Get Config

```http
GET /api/config
```

Returns the full current configuration including server, DNS, blocking, logging, and database settings.

`restart_required` is `true` while a saved change is waiting for a server restart to take effect — set by `POST /api/config` (anything but upstream pools), `POST /api/settings`, and the TLS certificate upload/generate endpoints. It is held in memory, so restarting the server resets it; the web UI's restart banner follows it.

### Update Config

```http
POST /api/config
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

The merged configuration is validated before anything is applied. An invalid value — an unknown `block_mode` or `dnssec_mode`, an unparseable server or sinkhole address, a `local_dns_server` that is not an IP address or `IP:port`, a zero interval, timeout or capacity such as `cache_compaction_interval: 0`, or a session lifetime whose expiry is past the latest representable date such as `session_ttl_hours: 4294967295` — returns **400** with `{ "success": false, "error": "…" }` naming the key, and neither the live server nor the file changes. A request that is valid but cannot be carried out (no writable config file, a failed pool hot-reload or file write) returns 200 with `success: false`.

The file is rewritten atomically (a synced temp file renamed over it), so a crash mid-save leaves the old or the new file, never a truncated one. The new file keeps the old one's mode, owner and group. When the file cannot be replaced — a Docker single-file bind mount, a directory the server cannot write, or an owner or group the server cannot give the new file — it is rewritten in place instead.

### Reload Config

```http
POST /api/config/reload
```

Reloads the configuration from the TOML file without restarting the server. DNS, blocking, and cache settings take effect immediately. Server-level settings (ports, pihole_compat) require a full restart. A file that fails to parse or validate is reported with `success: false` and the running configuration is kept.

The file is loaded the way startup loads it: command-line overrides the server was started with (`--dns-port`, `--web-port`, `--bind`, `--database`, `--log-level`) still win over the file. Changed upstream pools are rebuilt and swapped in live, as with `POST /api/config`; if that fails, nothing changes. A reload waits for any config save or backup import in progress, so it never interleaves with one. The Pi-hole `POST /api/action/restartdns` runs the same reload.

### Get Settings

```http
GET /api/settings
```

Returns DNS-specific settings (non-FQDN blocking, PTR blocking, local domain).

### Update Settings

```http
POST /api/settings
```

**Full replace** — unlike `POST /api/config` (a partial update), this endpoint overwrites the entire DNS settings form. Any field you omit reverts to its default: an omitted `sinkhole_ipv4` clears a previously-set sinkhole, an omitted `block_mode` resets it to `null_ip`. Send the complete object:

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

The response carries `restart_required`: `true` when the save changed a setting (these only take effect after a restart), `false` when the form was saved unchanged.

---

## TLS Certificates

Manage the certificate used for the HTTPS web interface.

### TLS Status

```http
GET /api/tls/status
```

Returns the current certificate status: whether TLS is enabled, whether the cert
and key files exist, the certificate subject, expiry (`cert_not_after`) and
whether it is currently valid.

### Upload Certificates

```http
POST /api/tls/upload
Content-Type: multipart/form-data
```

Uploads a PEM `cert` and `key` pair via multipart form fields.

**Error codes:** `400 Bad Request` (missing or invalid files), `401 Unauthorized`

### Generate Self-Signed

```http
POST /api/tls/generate?force=true
```

Generates a self-signed certificate/key pair. Pass `?force=true` to overwrite
existing files.

**Error codes:** `400 Bad Request` (files already exist — use `?force=true`), `401 Unauthorized`

---

## Configuration Backup

Export and import the full Ferrous DNS configuration (blocklists, allowlists,
groups, clients, custom domains, settings) as a JSON snapshot.

### Export Config

```http
GET /api/config/export
```

Returns a backup JSON document as a download (`Content-Disposition: attachment`,
filename `ferrous-backup-YYYY-MM-DD.json`).

### Import Config

```http
POST /api/config/import
Content-Type: multipart/form-data
```

Restores configuration from a previously exported backup file uploaded as a
multipart field. Returns an import summary describing what was applied.

**Error codes:** `400 Bad Request` (invalid backup file), `401 Unauthorized`

---

## Auth Endpoints

### Auth Status

```http
GET /api/auth/status
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
POST /api/auth/setup
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
POST /api/auth/login
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
POST /api/auth/logout
```

Invalidates the current session. **Public** — no auth required (clears session if present).

### Change Password

```http
POST /api/auth/password
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
GET /api/auth/sessions
```

Returns all active sessions. **Protected**.

### Revoke Session

```http
DELETE /api/auth/sessions/{id}
```

Revokes a specific session by ID. **Protected**. Any authenticated caller — any user's session or any API token — can revoke any user's session, including the admin's; there is no ownership or role check.

---

## API Tokens

Named API tokens for programmatic access. Tokens are stored as SHA-256 hashes — the full token is only shown once at creation.

### List Tokens

```http
GET /api/api-tokens
```

Returns all tokens. Only the token prefix is shown in the listing.

### Create Token

```http
POST /api/api-tokens
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
PUT /api/api-tokens/{id}
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
DELETE /api/api-tokens/{id}
```

---

## User Management

!!! warning "Roles are informational"
    Every user has a `role` (`admin` or `viewer`), stored on the account and its sessions and shown in the UI and API responses. **Nothing enforces it**: a `viewer` can call every protected endpoint, including configuration changes, user management and API tokens. Give accounts only to people you would trust with full access.

### List Users

```http
GET /api/users
```

Returns all users. **Protected**.

### Create User

```http
POST /api/users
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
DELETE /api/users/{id}
```

---

## Cache

### Cache Stats

```http
GET /api/cache/stats
```

Returns cache hit/miss counts, hit rate, and total entries.

### Cache Metrics

```http
GET /api/cache/metrics
```

Returns detailed cache metrics: hits, misses, evictions, insertions, optimistic refreshes, lazy deletions, compactions, hit rate.

### List Cache Entries

```http
GET /api/cache/entries?limit=25&offset=0&sort=cached_at&order=desc
```

Returns the entries currently held in the positive cache, with filtering, ordering, and pagination.

| Parameter | Type | Description |
|:----------|:-----|:------------|
| `limit` | integer | Max results (default: 25, max: 500) |
| `offset` | integer | Pagination offset |
| `domain` | string | Case-insensitive substring match on the cached domain |
| `type` | string | Record type name, e.g. `A`, `AAAA`, `CNAME` |
| `sort` | string | `hits`, `cached_at`, `expires_at`, `domain`, or `type` (default: `cached_at`) |
| `order` | string | `asc` or `desc` (default: `desc`) |

The response is `{ "data": [...], "total": 0, "records_total": 0, "limit": 25, "offset": 0 }`, where `total` counts the entries matching the filters and `records_total` counts every entry in the cache. Each item carries `domain`, `type`, `answers`, `canonical_name`, `dnssec_status`, `ttl`, `remaining_ttl`, `cached_at`, `expires_at`, `hits`, `last_access`, `permanent`, and `stale`. Timestamps are UNIX epoch seconds; `remaining_ttl` and `expires_at` are `null` for permanent entries.

`hits` counts only lookups served from the shared cache — queries absorbed by the per-thread L1 cache are not included, so hot A/AAAA records report fewer hits than they actually served.

### Delete Cache Entry

```http
DELETE /api/cache/entries?domain=example.com&type=A
```

Removes a single cache entry. Returns `204 No Content` on success, `404` if the entry is not cached, and `400` if the record type is unknown.

---

## Upstream Health

### Health Summary

```http
GET /api/upstream/health
```

Returns health status per upstream server (Healthy / Unhealthy).

### Health Detail

```http
GET /api/upstream/health/detail
```

Returns detailed health information per upstream: pool name, strategy, latency metrics, failure counts.

---

## Clients

### List Clients

```http
GET /api/clients?limit=1000
```

Returns all detected clients with IP, MAC, hostname, group, query count, and last seen.

### Client Stats

```http
GET /api/clients/stats
```

Returns per-client query statistics.

### Create Manual Client

```http
POST /api/clients
```

```json
{
  "name": "Living Room TV",
  "ip": "192.168.1.50"
}
```

### Update Client

```http
PATCH /api/clients/{id}
```

```json
{
  "name": "New Name"
}
```

### Delete Client

```http
DELETE /api/clients/{id}
```

### Assign Client to Group

```http
PUT /api/clients/{id}/group
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
GET /api/client-subnets
```

### Create Subnet

```http
POST /api/client-subnets
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
DELETE /api/client-subnets/{id}
```

---

## Groups

### List Groups

```http
GET /api/groups
```

### Create Group

```http
POST /api/groups
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
GET /api/groups/{id}
```

### Update Group

```http
PUT /api/groups/{id}
```

### Delete Group

```http
DELETE /api/groups/{id}
```

Returns `409` if the group still has assigned clients. Managed domains (including the rules generated for a blocked service), regex filters, blocklist and allowlist memberships, blocked services, Safe Search settings, client subnets and schedule assignments are removed with the group, and the block filter is reloaded so they stop applying immediately; query-log entries keep their data but lose the group attribution.

### Get Group Clients

```http
GET /api/groups/{id}/clients
```

---

## Blocklist Sources

### List Sources

```http
GET /api/blocklist-sources
```

### Create Source

```http
POST /api/blocklist-sources
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
GET /api/blocklist-sources/{id}
```

### Update Source

```http
PUT /api/blocklist-sources/{id}
```

### Delete Source

```http
DELETE /api/blocklist-sources/{id}
```

### Sync Sources

```http
POST /api/blocklist-sources/{id}/sync
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
GET /api/whitelist-sources
```

### Create Source

```http
POST /api/whitelist-sources
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
GET    /api/whitelist-sources/{id}
PUT    /api/whitelist-sources/{id}
DELETE /api/whitelist-sources/{id}
```

Creating, updating or deleting a whitelist source rebuilds the block filter, as blocklist source changes do, so the change applies without waiting for the daily sync. The rebuild re-downloads every enabled list.

---

## Managed Domains

Individual domains added to the blocklist or allowlist via the dashboard.

### List Domains

```http
GET /api/managed-domains?limit=100&offset=0
```

### Create Domain

```http
POST /api/managed-domains
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
GET    /api/managed-domains/{id}
PUT    /api/managed-domains/{id}
DELETE /api/managed-domains/{id}
```

`PUT` is a partial update: an absent field keeps its value. Send `"comment": null` to clear the comment.

---

## Regex Filters

### List Filters

```http
GET /api/regex-filters
```

### Create Filter

```http
POST /api/regex-filters
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
GET    /api/regex-filters/{id}
PUT    /api/regex-filters/{id}
DELETE /api/regex-filters/{id}
```

`PUT` is a partial update: an absent field keeps its value. Send `"comment": null` to clear the comment.

---

## Block Filter Stats

```http
GET /api/block-filter/stats
```

Returns blocking engine statistics: total domains in blocklist, total in allowlist, filter size.

---

## Blocklist & Allowlist (Compiled)

### Get Active Blocklist

```http
GET /api/blocklist
```

Returns the full compiled blocklist currently in memory.

### Get Active Allowlist

```http
GET /api/whitelist
```

Returns the full compiled allowlist currently in memory.

---

## Services (1-Click Blocking)

### Service Catalog

```http
GET /api/services/catalog
```

Returns all available service categories (built-in + custom).

```http
GET /api/services/catalog/{id}
```

Returns a specific service definition with its domain list.

### Blocked Services

```http
GET /api/services?group_id=1
```

Returns services currently blocked for a group.

### Block Service

```http
POST /api/services
```

```json
{
  "service_id": "facebook",
  "group_id": 1
}
```

### Unblock Service

```http
DELETE /api/services/{service_id}/groups/{group_id}
```

---

## Custom Services

Define your own blockable service categories.

### List / Create

```http
GET  /api/custom-services
POST /api/custom-services
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
GET    /api/custom-services/{id}
PATCH  /api/custom-services/{id}
DELETE /api/custom-services/{id}
```

---

## Safe Search

### Get Configs

```http
GET /api/safe-search/configs
GET /api/safe-search/configs/{group_id}
```

### Toggle Safe Search

```http
POST /api/safe-search/configs/{group_id}
```

```json
{
  "platform": "google",
  "enabled": true
}
```

### Delete Configs

```http
DELETE /api/safe-search/configs/{group_id}
```

---

## Local DNS Records

Static A/AAAA records served directly from cache.

### List Records

```http
GET /api/local-records
```

### Create Record

```http
POST /api/local-records
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
PUT    /api/local-records/{id}
DELETE /api/local-records/{id}
```

---

## Schedule Profiles

Time-based blocking profiles for parental controls.

### List / Create Profiles

```http
GET  /api/schedule-profiles
POST /api/schedule-profiles
```

```json
{
  "name": "School Hours",
  "description": "Block social media during school"
}
```

### Get / Update / Delete Profile

```http
GET    /api/schedule-profiles/{id}
PUT    /api/schedule-profiles/{id}
DELETE /api/schedule-profiles/{id}
```

### Manage Time Slots

```http
POST   /api/schedule-profiles/{id}/slots
DELETE /api/schedule-profiles/{id}/slots/{slot_id}
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
GET    /api/groups/{id}/schedule
PUT    /api/groups/{id}/schedule
DELETE /api/groups/{id}/schedule
```

```json
{
  "profile_id": 1
}
```

---

## Pi-hole v6 Compatibility API

When `pihole_compat = true`, the Pi-hole v6 endpoints below are available at
`/api/*` (and the native API moves to `/ferrous/api/*`). The compatibility layer
is **not read-only** — it implements full CRUD for domains, lists, groups and
clients, a blocking toggle, and the Pi-hole action endpoints.

With `[auth]` enabled, every endpoint except `/api/auth` needs the `sid` from
`POST /api/auth` in an `X-FTL-SID` header (or a `sid` header, or `?sid=`); the
native `X-Api-Key` header is not read here — send an API token as the password
instead. See [Pi-hole Compatibility > Authentication](features/pihole-compat.md#authentication).

**Auth & session**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth` | Pi-hole v6 login (session-based) |
| `GET` | `/api/auth` | Session status |
| `DELETE` | `/api/auth` | Logout |

**Stats & history**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/stats/summary` | Dashboard summary stats |
| `GET` | `/api/stats/history` | Query history timeline (also at `/api/history`) |
| `GET` | `/api/stats/top_blocked` | Top blocked domains |
| `GET` | `/api/stats/top_clients` | Top querying clients |
| `GET` | `/api/stats/top_domains` | Top allowed domains (`?blocked=true` for blocked) |
| `GET` | `/api/stats/query_types` | Query type distribution |
| `GET` | `/api/stats/upstreams` | Upstream usage |
| `GET` | `/api/stats/recent_blocked` | Most recently blocked domain |
| `GET` | `/api/history/clients` | Per-client query totals (last 24 h) |

Several of these are mirrored under `/api/stats/database/*` for Pi-hole clients.

**Queries & search**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/queries` | Paginated query log (filters: domain, client, status, …) |
| `GET` | `/api/queries/suggestions` | Filter suggestions |
| `GET` | `/api/search/{domain}` | Check if a domain would be blocked |

**DNS blocking toggle**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/dns/blocking` | Current blocking status (`timer`: seconds left, or `null`) |
| `POST` | `/api/dns/blocking` | Set blocking (optional `timer`: flip back after N seconds) |

**Domains (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/domains` | List all domains |
| `GET` | `/api/domains/{type}` | List by type (`allow`/`deny`) |
| `GET` | `/api/domains/{type}/{kind}` | List by type and kind (`exact`/`regex`) |
| `POST` | `/api/domains/{type}/{kind}` | Create a domain |
| `PUT` | `/api/domains/{type}/{kind}/{domain}` | Update a domain |
| `DELETE` | `/api/domains/{type}/{kind}/{domain}` | Delete a domain |
| `POST` | `/api/domains:batchDelete` | Batch delete |

**Lists / adlists (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/lists` | List adlists (optional `?type=allow\|block`) |
| `POST` | `/api/lists?type=allow\|block` | Create an adlist |
| `GET` | `/api/lists/{list}` | Lists with this address or id (optional `?type=`) |
| `PUT` | `/api/lists/{list}?type=allow\|block` | Update an adlist |
| `DELETE` | `/api/lists/{list}?type=allow\|block` | Delete an adlist |
| `POST` | `/api/lists:batchDelete` | Batch delete (`[{item, type}]`) |

**Groups (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/groups` | List groups |
| `POST` | `/api/groups` | Create a group |
| `GET` | `/api/groups/{name}` | Get a group |
| `PUT` | `/api/groups/{name}` | Update a group |
| `DELETE` | `/api/groups/{name}` | Delete a group |
| `POST` | `/api/groups:batchDelete` | Batch delete |

**Clients (CRUD)**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/clients` | List clients (`limit`, `offset`) |
| `POST` | `/api/clients` | Create a client |
| `GET` | `/api/clients/_suggestions` | IP/hostname suggestions |
| `PUT` | `/api/clients/{client}` | Update a client (by IP) |
| `DELETE` | `/api/clients/{client}` | Delete a client (by IP) |
| `POST` | `/api/clients:batchDelete` | Batch delete |

**Info**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/info/version` | Version info |
| `GET` | `/api/info/ftl` | FTL daemon info |
| `GET` | `/api/info/system` | Host system info |
| `GET` | `/api/info/host` | Host hostname |
| `GET` | `/api/info/database` | Query database info |

**Actions**

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/action/gravity` | Trigger a blocklist (gravity) reload |
| `POST` | `/api/action/restartdns` | Reload configuration in-memory |
| `POST` | `/api/action/flush/logs` | Clean up old query logs |

See [Pi-hole Compatibility](features/pihole-compat.md) for details.
