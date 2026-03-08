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

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth` | Login — returns a session token (`sid`) |
| `GET` | `/api/auth` | Get current session status |
| `DELETE` | `/api/auth` | Logout — invalidate session |
| `GET` | `/api/stats/summary` | Dashboard summary (queries, blocked, percentage, clients) |
| `GET` | `/api/stats/history` | Query history timeline for charts |
| `GET` | `/api/stats/top_blocked` | Top blocked domains |
| `GET` | `/api/stats/top_clients` | Top querying clients |
| `GET` | `/api/stats/query_types` | Query type distribution (A, AAAA, CNAME, etc.) |

---

## Authentication

The Pi-hole API uses **session-based authentication**:

1. `POST /api/auth` with `{"password": "your-api-key"}` — returns a session token
2. Include the session token in subsequent requests via the `sid` cookie or header

The Pi-hole API password is the same `api_key` configured in `ferrous-dns.toml`.

!!! important "Independent auth systems"
    The Pi-hole session (`sid`) and the Ferrous API key (`X-Api-Key`) are completely independent authentication systems. Authenticating with one does not grant access to the other.

---

## Compatible Third-Party Tools

The following tools and integrations work with Ferrous DNS in Pi-hole compat mode:

| Tool | Status | Notes |
|:-----|:------:|:------|
| Pi-hole Android/iOS apps | Partial | Stats and summary endpoints work; management features vary |
| Grafana Pi-hole dashboards | Works | Stats and history endpoints are compatible |
| Home Assistant Pi-hole integration | Works | Uses summary stats endpoint |
| Custom scripts using Pi-hole API | Partial | Depends on which endpoints the script uses |

!!! note
    Ferrous DNS implements the most commonly used Pi-hole v6 **read-only** endpoints (stats, history, top lists). Management endpoints (adding blocklists, configuring DNS) should use the Ferrous DNS native [REST API](../api.md).

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

- Only read-only endpoints (stats, history, top lists) are currently implemented
- Pi-hole management endpoints (blocklist CRUD, DNS settings) are not available via the Pi-hole API — use the [Ferrous DNS API](../api.md)
- Gravity Sync is not supported (different database format)
- The Pi-hole web interface is not included — use the Ferrous DNS dashboard
