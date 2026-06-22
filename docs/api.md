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

---

## Configuration

### Get Config

```http
GET /api/config
```

Returns the full current configuration including server, DNS, blocking, logging, and database settings.

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

### Reload Config

```http
POST /api/config/reload
```

Reloads the configuration from the TOML file without restarting the server. DNS, blocking, and cache settings take effect immediately. Server-level settings (ports, pihole_compat) require a full restart.

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

`sinkhole_ipv4` / `sinkhole_ipv6` set a custom block target for `null_ip` mode (empty string = the null address `0.0.0.0` / `::`). A non-empty value that is not a valid address of the matching family is rejected with `{ "success": false, "error": "Invalid IPv4 sinkhole address: …" }` and nothing is saved. See [Custom Sinkhole IP](configuration/blocking.md#custom-sinkhole-ip).

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
POST /api/auth/change-password
```

Changes the admin password. **Protected** — requires valid session or API token.

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

Revokes a specific session by ID. **Protected**.

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
  "password": "secure-password"
}
```

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
  "description": "Children's devices"
}
```

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
  "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
  "enabled": true
}
```

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
| `GET` | `/api/dns/blocking` | Current blocking status |
| `POST` | `/api/dns/blocking` | Enable/disable blocking (optional `timer`) |

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
| `GET` | `/api/lists` | List adlists |
| `POST` | `/api/lists` | Create an adlist |
| `GET` | `/api/lists/{id}` | Get an adlist |
| `PUT` | `/api/lists/{id}` | Update an adlist |
| `DELETE` | `/api/lists/{id}` | Delete an adlist |
| `POST` | `/api/lists:batchDelete` | Batch delete |

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
