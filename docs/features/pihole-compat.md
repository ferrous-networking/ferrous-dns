# Pi-hole Compatibility

Ferrous DNS can expose a Pi-hole v6 compatible API, making it a drop-in replacement for existing Pi-hole integrations, dashboards, and automation scripts.

---

## Enabling Compatibility Mode

```toml
[server]
pihole_compat = true
```

!!! note "Restart required"
    Changing `pihole_compat` requires a server restart to take effect.

---

## How It Works

When `pihole_compat = true`:

| Path | API |
|:-----|:----|
| `/api/*` | Pi-hole v6 compatible API |
| `/ferrous/api/*` | Ferrous DNS native API |
| `/` | Ferrous DNS dashboard (unchanged) |

The Ferrous dashboard automatically detects the correct API prefix via the `/ferrous-config.js` endpoint — no manual configuration needed.

When `pihole_compat = false` (default):

| Path | API |
|:-----|:----|
| `/api/*` | Ferrous DNS native API |
| `/` | Ferrous DNS dashboard |

---

## Supported Pi-hole v6 Endpoints

The compatibility layer is **not read-only** — it implements full CRUD for
domains, lists, groups and clients, a blocking enable/disable toggle, and the
Pi-hole action endpoints. All paths below are served under `/api/*` when
`pihole_compat = true`.

!!! tip "Interactive spec"
    The Pi-hole layer publishes its own OpenAPI document at `GET /api/openapi.json`
    with a built-in Scalar UI at `GET /api/docs`. See the
    [REST API reference](../api.md#interactive-documentation-openapi-scalar) for the
    full route table.

### Authentication

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth` | Login — returns a session token (`sid`) |
| `GET` | `/api/auth` | Get current session status |
| `DELETE` | `/api/auth` | Logout — invalidate session |

### Statistics & history

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/stats/summary` | Dashboard summary (queries, blocked, percentage, clients) |
| `GET` | `/api/stats/history` | Query history timeline for charts |
| `GET` | `/api/stats/top_blocked` | Top blocked domains |
| `GET` | `/api/stats/top_clients` | Top querying clients |
| `GET` | `/api/stats/top_domains` | Top allowed domains (`?blocked=true` for blocked) |
| `GET` | `/api/stats/query_types` | Query type distribution (A, AAAA, CNAME, etc.) |
| `GET` | `/api/stats/upstreams` | Upstream DNS server usage |
| `GET` | `/api/stats/recent_blocked` | Most recently blocked domain |
| `GET` | `/api/history/clients` | Per-client query totals for the last 24 h |

!!! note "Database aliases"
    For Pi-hole compatibility several stats endpoints are also reachable under
    `/api/stats/database/*` (`summary`, `top_domains`, `top_clients`, `upstreams`,
    `query_types`), and `/api/stats/history` is mirrored at `/api/history`.

### Query log & search

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/queries` | Paginated query log (filters: `domain`, `client`, `status`, `cursor`, `length`, `start`) |
| `GET` | `/api/queries/suggestions` | Categorised filter suggestions from recent queries |
| `GET` | `/api/search/{domain}` | Check whether a domain would be blocked (optional `?client`) |

### DNS blocking toggle

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/dns/blocking` | Current blocking status |
| `POST` | `/api/dns/blocking` | Enable/disable blocking (optional `timer` to auto re-enable) |

### Domains (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/domains` | List all managed and regex domains |
| `GET` | `/api/domains/{type}` | List by type (`allow` / `deny`) |
| `GET` | `/api/domains/{type}/{kind}` | List by type and kind (`exact` / `regex`) |
| `POST` | `/api/domains/{type}/{kind}` | Create a domain entry |
| `PUT` | `/api/domains/{type}/{kind}/{domain}` | Update a domain entry |
| `DELETE` | `/api/domains/{type}/{kind}/{domain}` | Delete a domain entry |
| `POST` | `/api/domains:batchDelete` | Batch delete domains |

### Lists / adlists (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/lists` | List all adlists |
| `POST` | `/api/lists` | Create an adlist |
| `GET` | `/api/lists/{id}` | Get an adlist by id |
| `PUT` | `/api/lists/{id}` | Update an adlist |
| `DELETE` | `/api/lists/{id}` | Delete an adlist |
| `POST` | `/api/lists:batchDelete` | Batch delete adlists |

### Groups (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/groups` | List all groups |
| `POST` | `/api/groups` | Create a group |
| `GET` | `/api/groups/{name}` | Get a group by name |
| `PUT` | `/api/groups/{name}` | Update a group |
| `DELETE` | `/api/groups/{name}` | Delete a group |
| `POST` | `/api/groups:batchDelete` | Batch delete groups |

### Clients (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/clients` | List all clients (`limit`, `offset`) |
| `POST` | `/api/clients` | Create a client |
| `GET` | `/api/clients/_suggestions` | IP/hostname suggestions |
| `PUT` | `/api/clients/{client}` | Update a client (by IP) |
| `DELETE` | `/api/clients/{client}` | Delete a client (by IP) |
| `POST` | `/api/clients:batchDelete` | Batch delete clients |

### Info

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/info/version` | Version info |
| `GET` | `/api/info/ftl` | FTL daemon info |
| `GET` | `/api/info/system` | Host system info (load, memory, disk) |
| `GET` | `/api/info/host` | Host hostname |
| `GET` | `/api/info/database` | Query database info |

### Actions

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/action/gravity` | Trigger a blocklist (gravity) reload |
| `POST` | `/api/action/restartdns` | Reload configuration in-memory (no process restart) |
| `POST` | `/api/action/flush/logs` | Clean up old query logs |

---

## Authentication

The Pi-hole v6 compatible API uses **session-based authentication**, matching the same flow as Pi-hole v6:

1. `POST /api/auth` with `{"password": "your-password"}` — creates a session and returns a session token
2. Include the session token in subsequent requests via the `sid` cookie or header

The Pi-hole API uses the same authentication backend as the Ferrous DNS native API. The admin password configured in the `[auth]` section is used for both.

!!! note "Shared auth backend"
    Since v0.7.0, Pi-hole compat auth and Ferrous DNS auth share the same session system. A session created via `POST /api/auth` (Pi-hole) is also valid for Ferrous DNS native endpoints, and vice versa.

---

## Compatible Third-Party Tools

The following tools and integrations work with Ferrous DNS in Pi-hole compat mode:

| Tool | Status | Notes |
|:-----|:------:|:------|
| Pi-hole Android/iOS apps | Partial | Stats, summary and most management endpoints work; coverage varies by app version |
| Grafana Pi-hole dashboards | Works | Stats and history endpoints are compatible |
| Home Assistant Pi-hole integration | Works | Uses summary stats and the blocking toggle |
| Custom scripts using Pi-hole API | Partial | Depends on which endpoints the script uses |

!!! note
    Ferrous DNS implements the commonly used Pi-hole v6 endpoints — stats, history and top lists **plus** management: full CRUD for domains, lists, groups and clients, the DNS blocking toggle, and the action endpoints (gravity, restartdns, flush logs). You can also drive these through the Ferrous DNS native [REST API](../api.md).

---

## Migrating from Pi-hole

### Step 1: Export Your Pi-hole Configuration

Note your current Pi-hole settings:

- Upstream DNS servers
- Blocklist URLs (Settings > Blocklists)
- Custom blocked domains (Local DNS > DNS Records)
- Client groups and assignments

### Step 2: Configure Ferrous DNS

Transfer your settings to `ferrous-dns.toml`:

```toml
[server]
pihole_compat = true    # keep Pi-hole API for existing integrations

[[dns.pools]]
name = "default"
strategy = "Parallel"
priority = 1
servers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[blocking]
enabled = true
```

### Step 3: Add Blocklists

Add your Pi-hole blocklist URLs via the Ferrous DNS dashboard:

1. Open `http://<server>:8080`
2. Go to **DNS Filter > Blocklist Sources**
3. Add each URL and click **Sync**

### Step 4: Update DNS on Your Network

Point your router's DHCP DNS setting to your Ferrous DNS server IP. Clients will switch over as their DHCP leases renew.

### Step 5: Update Integrations

If you have tools pointing to Pi-hole's API:

- **Same server IP**: no changes needed — `/api/*` continues to work
- **Different server**: update the IP/hostname in your integration

---

## Limitations

- Management is exposed (domains, lists, groups, clients, blocking toggle, gravity/restartdns/flush actions), but not every niche Pi-hole v6 endpoint is implemented — request payloads and field names track Pi-hole closely but may differ in edge cases
- `restartdns` reloads configuration in-memory; it does not restart the process, and `gravity` reloads blocklists rather than re-downloading via Pi-hole's gravity pipeline
- Gravity Sync is not supported (different database format)
- The Pi-hole web interface is not included — use the Ferrous DNS dashboard
