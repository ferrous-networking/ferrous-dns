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
| `/ferrous/api/v1/*` | Ferrous DNS native API |
| `/` | Ferrous DNS dashboard (unchanged) |

When `pihole_compat = false` (default):

| Path | API |
|:-----|:----|
| `/ferrous/api/v1/*` | Ferrous DNS native API |
| `/` | Ferrous DNS dashboard |

The native API stays at `/ferrous/api/v1` in both modes, so switching Pi-hole compatibility on or off never moves it. Before v0.10.0 it moved between `/api` and `/ferrous/api`; those bases now redirect, see [Migrating from `/api` and `/ferrous/api`](../api.md#migrating-from-api-and-ferrousapi).

---

## Supported Pi-hole v6 Endpoints

The compatibility layer is **not read-only** — it implements full CRUD for
domains, lists, groups and clients, a blocking enable/disable toggle, and the
Pi-hole action endpoints. All paths below are served under `/api/*` when
`pihole_compat = true`, and each one answers with the response shape and types
of Pi-hole's FTL.

Request bodies are read as JSON whatever their `Content-Type` says, as FTL does
(Homarr, for one, sends `text/plain`). A body that does not parse gets `400`
`bad_request`, and every error reply is FTL's envelope:
`{"error": {"key": "...", "message": "...", "hint": null}}`, where `hint` is a
string or `null`. A path FTL does not route is answered `404` `not_found` with
the path as `hint`, before any session check, and a known path with the wrong
method `405` `method_not_allowed` with the method as `hint`.

!!! tip "Interactive spec"
    The Pi-hole layer publishes its own OpenAPI document at `GET /api/openapi.json`
    with a built-in Scalar UI at `GET /api/docs`. See the
    [REST API reference](../api.md#interactive-documentation-openapi-scalar) for the
    full route table.

### Authentication

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth` | Login — returns a session token (`sid`). Public |
| `GET` | `/api/auth` | Current session; `401` with the session object when there is no valid one. Public |
| `DELETE` | `/api/auth` | Logout — invalidate session |
| `GET` | `/api/auth/sessions` | Every live session, oldest first; `current_session` marks the one the request presented |
| `DELETE` | `/api/auth/session/{id}` | End the session listed under `id`. `400` `bad_request` when `id` is not a number, is negative, or names no live session |
| `GET` | `/api/info/login` | `{"dns": true, "https_port": N}`, which clients such as Homarr probe to detect Pi-hole v6. Public |

### Statistics & history

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/stats/summary` | Dashboard summary: query totals, `types` per FTL query type, `status` and `replies` counters, clients and gravity size. `forwarded` counts only upstream answers; `cached` includes local DNS records |
| `GET` | `/api/history` | Query timeline: 145 ten-minute buckets with `total`, `cached`, `blocked` and `forwarded`, stamped at the bucket centre. Also served at `/api/stats/history` |
| `GET` | `/api/history/clients` | Per-client series in the same buckets; `N` series (default 10, `0` for all), the rest summed under `others` |
| `GET` | `/api/stats/top_domains` | Top allowed domains (`?blocked=true` for blocked); `count` (default 10) |
| `GET` | `/api/stats/top_blocked` | Top blocked domains; `count` (default 10) |
| `GET` | `/api/stats/top_clients` | Top clients by queries, or by blocked queries with `?blocked=true`; `count` (default 10) |
| `GET` | `/api/stats/query_types` | Query count per type: `{"types": {"A": n, ...}}` |
| `GET` | `/api/stats/upstreams` | Array of answer sources: the `blocklist` and `cache` pseudo-entries (port `-1`), then each upstream server, merged across pools |
| `GET` | `/api/stats/recent_blocked` | Most recently blocked domains, newest first; `count` (default 1) |

These live endpoints also take `from`, a Ferrous extension giving the window in hours back from now (default 24), and still honour `limit` as an alias of `count`.

### Long-term statistics

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/stats/database/summary` | `sum_queries`, `sum_blocked`, `percent_blocked` and `total_clients` for the window |
| `GET` | `/api/stats/database/top_domains` | Top allowed domains (`?blocked=true` for blocked); `count` (default 10) |
| `GET` | `/api/stats/database/top_clients` | Top clients (`?blocked=true` ranks by blocked queries); `count` (default 10) |
| `GET` | `/api/stats/database/upstreams` | Answer sources, as `/api/stats/upstreams` |
| `GET` | `/api/stats/database/query_types` | Query count per type |

Each takes the window as Unix timestamps in `from` and `until`; both are required, and a request missing either is answered `400`.

### Query log & search

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/queries` | Query log, newest first. Filters: `from`, `until`, `domain`, `client_ip` (alias `client`), `client_name`, `upstream` (`ip#port`, `blocklist`, `cache` or `permitted`), `type`, `status`, `reply`, `dnssec`, `disk`. Paging: `length` (default 100, `0` or below for all, capped at 10000), `start`, `cursor`; `draw` is echoed |
| `GET` | `/api/queries/suggestions` | Filter values: top domains and clients of the last 24 h (`count`, default 30), upstreams as `ip#port`, and every FTL type, status, reply and DNSSEC name |
| `GET` | `/api/search/{domain}` | What holds the domain: exact domain-list entries, matching regex filters, and the blocklists then the allowlists that contain it. `partial`, `N` (rows per kind, default 20, at most 10000), `debug` |

The first `/api/queries` page pins `cursor` to the newest query; send it back with `start` to page through that snapshot, unshifted by queries logged since. A cursor past the newest query, or a filter value FTL does not know, is answered `400`. `until` is exclusive, `type=OTHER` selects every query type outside FTL's list, and `reply` selects by the same reply type each entry reports.

### DNS blocking toggle

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/dns/blocking` | `{"blocking": "enabled", "timer": null}`; `blocking` is `"enabled"` or `"disabled"`, `timer` the seconds left on a pending timer (fractional), `null` when none |
| `POST` | `/api/dns/blocking` | Set blocking: `{"blocking": false, "timer": 300}` — with a `timer` the mode flips back when it elapses. Replies with the resulting state |

As on Pi-hole, the timer works both ways: `{"blocking": true, "timer": N}` enables blocking now and disables it after `N` seconds. Only a number above zero starts a timer, fractions included; any other value (`true`, `null`, `0`) means none. Every `POST` replaces the pending timer, so one without `timer` cancels it. The timer lives in memory and does not survive a restart.

### Domains (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/domains` | List all managed and regex domains |
| `GET` | `/api/domains/{type}` | List by type (`allow` / `deny`) or kind (`exact` / `regex`); any other value is a domain looked up in every list |
| `GET` | `/api/domains/{type}/{kind}` | List by type and kind (`exact` / `regex`) |
| `GET` | `/api/domains/{type}/{kind}/{domain}` | One entry; an empty list when it does not exist |
| `POST` | `/api/domains/{type}/{kind}` | Add one domain or several: `domain` is a string or an array |
| `PUT` | `/api/domains/{type}/{kind}/{domain}` | Replace the entry, or create it; a body `type`/`kind` names the list it moves from |
| `DELETE` | `/api/domains/{type}/{kind}/{domain}` | Delete a domain entry |
| `POST` | `/api/domains:batchDelete` | Batch delete: `[{"item": "<domain>", "type": "deny", "kind": "exact"}]` |

### Replies of the CRUD endpoints

Domains, groups, clients and lists share FTL's conventions:

- `GET` replies with `{"domains": [...]}` (or `groups`, `clients`, `lists`); a name that matches nothing gives an empty array, not `404`.
- `POST` (`201`) and `PUT` (`200`) reply with the stored entries plus `"processed": {"success": [{"item"}], "errors": [{"item", "error"}]}`. A duplicate or invalid item lands in `processed.errors`; when every item fails the reply is `400` `database_error`. `PUT` on a domain replaces the entry, so an omitted `comment` becomes `null` and an omitted `enabled` becomes `true`.
- `:batchDelete` answers `204` when something was deleted and `404` when nothing matched.
- Dates are Unix seconds, and `comment` is always present (`null` when empty).
- Group ids follow FTL: the default group is id `0`, in replies and in requests.

### Lists / adlists (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/lists` | List all adlists (optional `?type=allow\|block`) |
| `POST` | `/api/lists?type=allow\|block` | Add one adlist or several: `address` is a string or an array |
| `GET` | `/api/lists/{list}` | Lists with this address (optional `?type=allow\|block`) |
| `PUT` | `/api/lists/{list}?type=allow\|block` | Replace an adlist (`comment`, `groups`, `enabled`), or create it |
| `DELETE` | `/api/lists/{list}?type=allow\|block` | Delete an adlist |
| `POST` | `/api/lists:batchDelete` | Batch delete: `[{"item": "<address>", "type": "block"}]` |

As in Pi-hole v6, `{list}` is the list's address, URL-encoded or not, and `type` says which table it lives in: blocklists and allowlists are stored separately, so the same address — or the same numeric id, which `{list}` also accepts — can name one of each. `POST`, `PUT` and `DELETE` require `?type=`; a missing or unknown type is rejected with `400` and changes nothing. A `batchDelete` item without a known type matches nothing, and `?type=` on `batchDelete` overrides every item's type. `GET /api/lists/{list}` without `type` returns the matches of both types. Each list in a reply carries `"type": "allow"` or `"type": "block"`, `date_updated` (the last successful download), and `status`, Pi-hole's code for how its last download went: `0` not tried yet, `1` updated, `2` unchanged, `3` failed with the previous copy still in use, `4` failed with no copy.

!!! warning "Changed in v0.9.19"
    Earlier versions ignored the list type on `/api/lists/{id}`, so an allowlist whose id matched a blocklist could not be read, updated or deleted — the request hit the blocklist instead. `type` in replies was `0`/`1` and is now `"block"`/`"allow"`; the type moved from the `POST` body to `?type=`; `PUT` no longer renames a list; and `batchDelete` takes Pi-hole's `[{item, type}]` array instead of `{"items": [...]}`.

### Groups (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/groups` | List all groups |
| `POST` | `/api/groups` | Add one group or several: `name` is a string or an array |
| `GET` | `/api/groups/{name}` | Get a group by name |
| `PUT` | `/api/groups/{name}` | Replace or create a group; a `name` in the body renames it |
| `DELETE` | `/api/groups/{name}` | Delete a group |
| `POST` | `/api/groups:batchDelete` | Batch delete: `[{"item": "<name>"}]` |

### Clients (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/clients` | List all clients |
| `POST` | `/api/clients` | Add one client or several: `client` is an IP address or a subnet (`10.0.0.0/24`), or an array of them |
| `GET` | `/api/clients/{client}` | One client (by IP or subnet); an empty list when unknown |
| `GET` | `/api/clients/_suggestions` | Devices the resolver has seen, most recently active first: `{"clients": [{hwaddr, macVendor, lastQuery, addresses, names}]}`; `count` (default 50) |
| `PUT` | `/api/clients/{client}` | Update a client (by IP or subnet), or create it |
| `DELETE` | `/api/clients/{client}` | Delete a client (by IP or subnet) |
| `POST` | `/api/clients:batchDelete` | Batch delete: `[{"item": "<ip or subnet>"}]` |

Each client carries `client` (its IP or subnet), `name` (`""` when unknown, and always for a subnet), `comment`, `date_added` (when it was added or first seen) and `date_modified` (its last change, its last query included). A subnet client is a Ferrous [client subnet](../api.md#client-subnets): every address in it uses its group. As in FTL, a write replaces the `comment`, so a `PUT` without one clears it.

### Info

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/info/login` | Public. `https_port` is the web port when the web server serves HTTPS, `0` on plain HTTP |
| `GET` | `/api/info/client` | Public. The caller's address, HTTP version, method and request headers |
| `GET` | `/api/info/version` | `{"version": {"core", "web", "ftl", "docker"}}`, each with `local` and `remote` |
| `GET` | `/api/info/ftl` | Resolver process info and domain/client counts, under `ftl` (`uptime` in milliseconds) |
| `GET` | `/api/info/system` | Uptime, memory (kB), processes and load, under `system` |
| `GET` | `/api/info/host` | Kernel `uname`, device `model` and `dmi` identifiers, under `host` |
| `GET` | `/api/info/sensors` | Every hwmon chip with its temperatures, and the CPU's, under `sensors` |
| `GET` | `/api/info/metrics` | DNS cache counters (`size`, `inserted`, `evicted`, `expired`), and FTL's reply and DHCP counters, under `metrics` |
| `GET` | `/api/info/messages` | FTL's diagnosis messages; always empty, Ferrous raises none |
| `GET` | `/api/info/messages/count` | `{"count": 0}` |
| `DELETE` | `/api/info/messages/{id}` | `404` with `{}`, since there is no message to delete |
| `GET` | `/api/info/database` | Database file `size` and metadata, and stored query counts |

### Network and DHCP

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/network/gateway` | Default routes, each with its interface's addresses of the same family |
| `GET` | `/api/network/routes` | The kernel's routing table |
| `GET` | `/api/network/interfaces` | Every interface with its type, flags, state, speed, byte counters and addresses |
| `GET` | `/api/network/devices` | Devices built from the known clients: the clients sharing a MAC address are one device, with their addresses most recently seen first; `max_devices` (default 10), `max_addresses` (default 3) |
| `GET` | `/api/dhcp/leases` | `{"leases": []}`: Ferrous serves no DHCP |
| `DELETE` | `/api/dhcp/leases/{ip}` | `400` `bad_request`, with FTL's hint `DHCP is not enabled` |

### PADD and endpoint list

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/padd` | The one-call summary PADD polls: summary figures, tops, blocking state, system and host. `full=false` leaves out `iface` and `version` |
| `GET` | `/api/endpoints` | Every documented route by HTTP method, built from the OpenAPI document the server serves |

### Actions

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/action/gravity` | Reload the blocklists and rebuild the block filter, streaming `text/plain` progress in the style of `pihole -g` (`?color=true` adds ANSI colours). As in FTL, a failure is reported in the text with `200` |
| `POST` | `/api/action/restartdns` | Reload configuration in-memory (no process restart), like `POST /ferrous/api/v1/config/reload`: upstream pools hot-reloaded, command-line overrides kept |
| `POST` | `/api/action/flush/logs` | Delete every stored query, and the history built from them, as FTL does |

`restartdns` and `flush/logs` reply `{"status": "success"}`.

!!! warning "Changed in v0.9.23"
    Replies now follow FTL's schemas field for field. Integrations written against earlier versions should check these routes and fields:

    - **Requests and errors**: bodies are read as JSON whatever the `Content-Type`; one that does not parse is `400` `bad_request`. Every error carries `hint`. An unknown path is a JSON `404` `not_found` and a wrong method a JSON `405` `method_not_allowed` (both had an empty body).
    - **Blocking**: `blocking` in replies is `"enabled"`/`"disabled"` (was `true`/`false`); `timer` is fractional seconds in replies, and a fractional `timer` is accepted in requests.
    - **Info**: `/info/version` is nested by component; `/info/ftl`, `/info/system` and `/info/host` are wrapped in `ftl`, `system` and `host`. FTL uptime is in milliseconds, memory in kB, `system.disk` is gone, `/info/host` reports `uname`/`model`/`dmi` instead of `hostname`, and `/info/database` reports `size` instead of `filesize`.
    - **Auth**: `GET /auth` without a valid session is `401` (was `200`); `totp` says whether 2FA is enrolled; `csrf` is left out without a valid session; `POST /auth` without `password` is `400`; `DELETE /auth` with `[auth]` disabled is `401`.
    - **Stats**:
        - `/stats/upstreams` is an array (was a map).
        - Top lists take `count`, default 10 (was `limit`, default 25).
        - The summary gains `status` and `replies`, `types` lists FTL's fixed types, `cached` includes local records, and the top-level `status` key is gone.
        - `/stats/query_types` is `{"types": {TYPE: count}}` (was `querytypes` with percentages).
        - `/stats/recent_blocked` is `{"blocked": [...]}` (was `domain`).
        - `/stats/database/*` take Unix `from`/`until`, both required (`from` was hours); the summary is `{sum_queries, sum_blocked, percent_blocked, total_clients}`.
    - **History**: `/history` is the documented route (`/stats/history` stays as an alias); buckets are stamped at their centre with real `cached` and `forwarded`. `/history/clients` is `{"history": [{timestamp, data}], "clients": {...}}`, keyed by IP.
    - **Queries**: `reply.time` is in seconds (was milliseconds); `reply.type` and `dnssec` use FTL's names; `upstream` is `ip#port` or `null` (was `udp://…` or `""`); the cursor pins a snapshot and is never `null`; `/queries/suggestions` is wrapped in `suggestions`.
    - **Search**: `/search/{domain}` is `{"search": {domains, gravity, results, parameters}}`; `?client` was removed.
    - **Domains, groups, clients, lists**:
        - Writes reply with `processed`; dates are Unix integers; `comment` is always present; the default group is id `0`.
        - A duplicate is reported in `processed.errors`, and `400` `database_error` when every item fails (was `409`).
        - `:batchDelete` takes `[{item, type, kind}]` for domains and `[{item}]` for groups and clients, and answers `404` when nothing matched.
        - `GET` on a missing group or list is `200` with an empty array (was `404`).
        - `PUT /domains/...` takes no `domain` in the body; `PUT /groups/{name}` with `name` renames.
        - Clients use `client` instead of `ip`, and `limit`/`offset` are gone; `/clients/_suggestions` is `{"clients": [...]}` of devices.
        - A client can be a subnet, and its `comment` is stored (was always `null`).
        - Lists gain `date_updated`, `number`, `invalid_domains` and `abp_entries`; `status` is Pi-hole's download code `0`–`4` (was a copy of `enabled`).
        - `unicode` on a domain entry is its decoded international form, and a non-ASCII exact domain is stored as punycode (was rejected).
    - **Actions**: `restartdns` and `flush/logs` reply `{"status": "success"}` only; `gravity` streams `text/plain`.
    - **Values that were `0`**: `unique_domains`, `frequency`/`query_frequency`, `gravity.last_update`, `%cpu`, `/padd` `cache.inserted`/`evicted` and the `dnsmasq.dns_cache_*` counters now carry real values; `clients.total` counts every known client.
    - **Search**: allowlists that hold the domain are listed in `gravity` and counted in `results.gravity.allow`.
    - **New routes**: `GET /api/info/login`, `/api/info/client`, `/api/info/sensors`, `/api/info/metrics`, `/api/info/messages*`, `/api/auth/sessions`, `DELETE /api/auth/session/{id}`, `/api/network/{gateway,routes,interfaces,devices}`, `/api/dhcp/leases*`, `/api/padd`, `/api/endpoints`, `/api/domains/{type}/{kind}/{domain}` and `/api/clients/{client}`.

---

## Authentication

With `[auth] enabled = true` (the default), every endpoint requires a session except `/api/auth`, `/api/info/login` and `/api/info/client`, which are public — the same rule as a Pi-hole that has a password set. With `[auth] enabled = false` the API is open, like a Pi-hole without a password: `GET` and `POST /api/auth` answer `{"valid": true, "sid": null, "validity": -1}`, and `DELETE /api/auth` answers `401`, since there is no session to end.

The login flow is Pi-hole v6's:

1. `POST /api/auth` with `{"password": "..."}` returns `session.sid`. The password can be:
    - the **admin password** from `[auth.admin]` — the Pi-hole API always logs in as that account, since Pi-hole has a single password; or
    - an **API token** (Settings > API > API Tokens), the equivalent of Pi-hole's *app password*. As on Pi-hole, it skips the second factor, so use one for unattended integrations — it is what the Home Assistant Pi-hole v6 integration asks for as its "API key".
2. If the admin account has TOTP enabled, send the code in the same request: `{"password": "...", "totp": 123456}`. Without it the reply is `400` (`bad_request`); a wrong code is `401` (`unauthorized`). A body without `password` is `400`, and an empty `password` sent with a valid `sid` returns that session. A wrong password is `401` even when a valid `sid` comes with it; that session stays valid.
3. Send the `sid` with every later request, in the `X-FTL-SID` header, a `sid` header, or the `?sid=` query parameter. Anything else gets `401` with `{"error": {"key": "unauthorized", ...}}`.
4. `DELETE /api/auth` with the same `sid` ends the session.

`GET /api/auth` returns the session object for the presented `sid`. Without a valid one the reply is `401`, still with the session object (`"valid": false`, `"sid": null`). In that object, `totp` tells whether the admin account has a second factor enrolled.

Failed logins count toward the same lockout as the dashboard login: after `login_rate_limit_attempts` wrong passwords or codes from one client, `POST /api/auth` answers `429` (`rate_limiting`) until `login_rate_limit_window_secs` has passed. See [Login lockout](security.md#login-lockout).

!!! note "Not supported"
    Pi-hole's `sid` **cookie** (sent with an `X-FTL-CSRF` header — what the Pi-hole web interface uses) and a `sid` inside the request body are not accepted. `session.csrf` is sent only with a valid session, and then as `null`. `validity` is the seconds left on the session (`session_ttl_hours`), not Pi-hole's sliding 30-minute timeout.

!!! warning "Changed in v0.9.19"
    Earlier versions served every Pi-hole endpoint without checking the session, and `POST /api/auth` accepted any password. Integrations that never logged in now need the admin password or an API token. An integration configured with a key that was never valid here — often an old Pi-hole app password — now gets `401`, and the server log shows `Pi-hole API login rejected`; add that same key as an API token (Settings > API > API Tokens > **Custom Token**) and the integration works again unchanged.

!!! note "Shared auth backend"
    Since v0.7.0, Pi-hole compat auth and Ferrous DNS auth share the same session system. A session created via `POST /api/auth` (Pi-hole) is also valid for Ferrous DNS native endpoints, and vice versa.

---

## Compatible Third-Party Tools

The following tools and integrations work with Ferrous DNS in Pi-hole compat mode:

| Tool | Status | Notes |
|:-----|:------:|:------|
| Homarr | Works | Pi-hole integration, DNS Hole Summary and DNS Hole Controls widgets |
| Home Assistant Pi-hole integration | Works | Loads through `/info/version`; summary sensors and the blocking switch, with or without a duration |
| Homepage | Works | `pihole` widget with `version: 6` |
| eko/pihole-exporter (Prometheus) | Works | Summary, top lists, upstreams and blocking status |
| Grafana Pi-hole dashboards | Works | Stats and history endpoints are compatible |
| Glance | Works | Pi-hole v6 widget; `/history` keeps its 145 buckets |
| Pi-hole Android/iOS apps | Partial | Stats, summary and most management endpoints work; coverage varies by app version |
| Custom scripts using Pi-hole API | Partial | Work on every served route; see [Limitations](#limitations) for the routes that are not |

Requests may be sent with any `Content-Type`; the body is read as JSON either way.

!!! note
    Ferrous DNS implements the Pi-hole v6 endpoints integrations use — stats, history and top lists **plus** management: full CRUD for domains, lists, groups and clients, the DNS blocking toggle, and the action endpoints (gravity, restartdns, flush logs). You can also drive these through the Ferrous DNS native [REST API](../api.md).

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
3. Add each URL and click **Save** — every list is downloaded and activated as
   soon as it is saved

### Step 4: Update DNS on Your Network

Point your router's DHCP DNS setting to your Ferrous DNS server IP. Clients will switch over as their DHCP leases renew.

### Step 5: Update Integrations

If you have tools pointing to Pi-hole's API:

- **Same server IP**: no changes needed — `/api/*` continues to work
- **Different server**: update the IP/hostname in your integration
- **Tools logged in with a Pi-hole app password**: create an API token with the same value (Settings > API > API Tokens > **Custom Token**) and they keep working unchanged

---

## Limitations

Every route served under `/api/*` answers with FTL's response shapes and types. The layer targets integrations — dashboards, exporters, home automation and scripts — not the Pi-hole web interface.

### FTL routes not served

They answer FTL's JSON `404` `not_found`.

- **Used only by the Pi-hole web interface**: `/auth/app` and `/auth/totp` (manage app passwords and 2FA in the Ferrous dashboard), `/action/flush/network`, `/action/flush/arp`, `DELETE /network/devices/{id}` (a device is built from client settings, which deleting would lose), `/history/database*`, `/logs/{dnsmasq,ftl,webserver}`
- **No equivalent in Ferrous DNS**: `/config*`, `/teleporter` (different backup format)
- **The Pi-hole web interface itself**: it authenticates with the `sid` cookie and an `X-FTL-CSRF` header, which this API does not accept. Use the Ferrous DNS dashboard.

### Values Ferrous DNS does not track

These fields keep FTL's type but carry a neutral value, or behave differently from FTL:

| Endpoint | Neutral values and differences |
|:---------|:-------------------------------|
| `/stats/summary` | Every `replies.*` is `0`. `frequency` is queries per second over the last minute (FTL averages 30 seconds); `unique_domains` counts the distinct domains of the window; `gravity.last_update` is the newest list download, since Ferrous has no gravity run; `clients.total` counts every known client |
| `/stats/upstreams` | `statistics.response` and `statistics.variance` are `0` (no per-server timing) |
| `/stats/database/*` | `until` is accepted but read as now; windows are minute-aligned; `total_clients` counts clients seen since `from` |
| `/info/ftl` | `antigravity` and `privacy_level` are `0`; of the `dnsmasq.*` counters only `dns_cache_inserted` and `dns_cache_live_freed` (evictions) are counted, the rest are `0`; `query_frequency` is as in the summary; `%cpu` is sampled on request and kept 10 seconds, the first sample averaging since the process started; `allow_destructive` is always `true` |
| `/info/system` | `%cpu` is sampled as in `/info/ftl`, the first sample averaging since boot |
| `/info/sensors` | Chips come in `hwmonN` order rather than directory order; `hot_limit` (`60`) and `unit` (`C`) are FTL's defaults |
| `/info/metrics` | `cache.expired` counts expired entries removed on lookup; `cache.immortal` is `0` and `cache.content` empty; every `replies.*` and `dhcp.*` counter is `0` |
| `/info/client` | Header names are lowercase |
| `/info/database` | The file type is `Regular file` or `Unknown`; owner names come from `/etc/passwd` and `/etc/group`, `null` when not found |
| `/auth/sessions` | `id` is a number derived from the session, not a slot index; `app` and `cli` are `false` and `x_forwarded_for` is `null`, as Ferrous does not record them; `tls.login` says whether the web server serves HTTPS |
| `/network/*` | Read from `/proc` and `/sys` rather than netlink: routes leave out the IPv4 local table, carry no `prefsrc` and report `protocol` as `unspec`; interfaces carry no `perm_address`, and their addresses no flags or lifetimes. Devices are built from clients; their `interface` and `macVendor` are `""` |
| `/queries` | A blocked `status` selects every blocked query; `status=CACHE` misses local records. `domain`, `client_ip` and `client_name` match as substrings with `*` only at the ends, and only one client filter applies at a time; `upstream` takes no wildcards. The `reply.type` of a blocked query, and the `reply` filter, follow the current block mode; the reply types Ferrous never logs (`DOMAIN`, `RRNAME`, `NOTIMP`, `DNSSEC`, `BLOB`) select nothing. `cname` and `list_id` are `null`, `ede` is `{"code": -1, "text": null}` |
| `/search/{domain}` | `partial` does not apply to lists; the manual block and allow lists and managed domains name no source; `gravity[].domain` is the searched domain, not the list line; `debug` adds nothing |
| `/domains` | One group per entry; an invalid regex lands in `processed.errors`; no `Location` header |
| `/clients` | IP addresses and subnets only (no MAC, hostname or interface); one group per client; address and subnet ids come from separate sequences; `GET` lists every known client, including discovered ones; `POST` of a known IP updates it rather than failing as a duplicate; `macVendor` is `null` |
| `/lists` | `number`, `invalid_domains` and `abp_entries` are `0`. `status` `2` means the download matched the copy in use, as Ferrous makes no conditional request. Copies are kept in memory, so after a restart a list whose download fails is `4` rather than `3`. Lookup by numeric id is a Ferrous extension |
| `/padd` | `%cpu` and `query_frequency` as in `/info/ftl`; `privacy_level` is `0`; DHCP fields are `false` or `""`; `sensors.hot_limit` (`60`) and `unit` (`C`) are FTL's defaults |
| `/endpoints` | Lists the documented routes only, not the `/stats/history` alias or the routes that take a list or client address containing `/` |

### Other differences

- `restartdns` reloads configuration in-memory (upstream pools included, command-line overrides kept); it does not restart the process, and `gravity` reloads Ferrous's blocklists rather than running Pi-hole's gravity database pipeline
- Gravity Sync and Nebula Sync are not supported: they copy Pi-hole's gravity database, `/teleporter` archives and `/config`, which have no Ferrous equivalent
