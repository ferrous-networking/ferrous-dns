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

## Authentication

When `api_key` is set in `ferrous-dns.toml`, all mutating requests (POST, PUT, PATCH, DELETE) require the API key header:

```http
X-Api-Key: your-secret-api-key
```

GET requests are not authenticated by default.

!!! note "Dashboard authentication"
    The web dashboard stores the API key in the browser's `localStorage` and sends it automatically via the `X-Api-Key` header. You can set the key in **Settings > Dashboard Session Key**.

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
    "api_key": "new-key",
    "pihole_compat": true
  }
}
```

To remove the API key:

```json
{
  "server": {
    "clear_api_key": true
  }
}
```

### Reload Config

```http
POST /api/config/reload
```

Reloads the configuration from the TOML file without restarting the server. DNS, blocking, and cache settings take effect immediately. Server-level settings (ports, API key, pihole_compat) require a full restart.

### Get Settings

```http
GET /api/settings
```

Returns DNS-specific settings (non-FQDN blocking, PTR blocking, local domain).

### Update Settings

```http
POST /api/settings
```

```json
{
  "never_forward_non_fqdn": true,
  "never_forward_reverse_lookups": true,
  "local_domain": "lan",
  "local_dns_server": "192.168.1.1:53"
}
```

---

## API Key Management

### Generate API Key

```http
POST /api/api-key/generate
```

Generates a new random API key. Returns the key — save it, as it cannot be retrieved again.

```json
{
  "key": "generated-base64-key"
}
```

!!! warning
    The generated key is not active until saved via `POST /api/config` and the server is restarted.

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

Returns blocking engine statistics: total domains in blocklist, total in allowlist, bloom filter size.

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

When `pihole_compat = true`, the following Pi-hole v6 endpoints are available at `/api/*`:

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/auth` | Get current session |
| `POST` | `/api/auth` | Login (returns session token) |
| `DELETE` | `/api/auth` | Logout |
| `GET` | `/api/stats/summary` | Dashboard summary stats |
| `GET` | `/api/stats/history` | Query history timeline |
| `GET` | `/api/stats/top_blocked` | Top blocked domains |
| `GET` | `/api/stats/top_clients` | Top querying clients |
| `GET` | `/api/stats/query_types` | Query type distribution |

See [Pi-hole Compatibility](features/pihole-compat.md) for details.
