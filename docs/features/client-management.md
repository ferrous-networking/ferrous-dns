# Client Management

Ferrous DNS automatically detects clients on your network and lets you organize them into groups with independent policies, schedules, and blocking rules.

---

## Client Detection

Ferrous DNS identifies clients by:

- **IP address** — always available
- **MAC address** — available when clients are on the same Layer 2 network (same subnet, no router between client and Ferrous DNS)
- **Hostname** — resolved via PTR lookup against the local DNS server configured in `local_dns_server`

### Configuration

```toml
[dns]
local_dns_server = "192.168.1.1:53"   # router/DHCP server for hostname resolution
```

Clients appear in the dashboard under **Clients** as soon as they make a DNS query.

---

## Client Groups

Group your clients to apply independent policies:

### Creating a Group

1. Go to **Clients > Groups** in the dashboard
2. Click **New Group**
3. Set a name (e.g. "Kids", "Work", "IoT", "Guest")
4. Assign clients to the group
5. Configure the group's blocklists, schedules, and forwarding

### Group Policies

Each group can have its own:

| Policy | Description |
|:-------|:------------|
| **Blocklists** | Which blocklists apply to this group |
| **Allowlist** | Domains always allowed for this group |
| **Safe Search** | Force safe search on search engines |
| **Scheduling** | Time-based blocking rules |
| **Conditional forwarding** | Route specific domains to internal resolvers |
| **Upstream** | Use different upstream DNS pools (planned) |

---

## Parental Controls & Scheduling

Time-based blocking lets you enforce internet policies automatically:

### Example Schedules

**School hours** (block social media during school days):
```text
Monday–Friday, 08:00–15:00 → block Social Media category
```

**Bedtime** (block internet entirely after hours):
```text
Sunday–Thursday, 21:00–07:00 → block all non-essential traffic
Friday–Saturday, 23:00–08:00 → block all non-essential traffic
```

**Work hours** (block entertainment at work devices):
```text
Monday–Friday, 09:00–18:00 → block Gaming, Streaming, Social Media
```

### Setting Up a Schedule

1. Go to **Clients > Groups > [Your Group] > Schedule**
2. Click **Add Schedule Rule**
3. Select days and time range
4. Choose which categories or blocklists to activate during this window
5. Save

The schedule evaluator runs every minute and activates/deactivates blocking rules automatically.

---

## Conditional Forwarding

Route specific domain queries to internal resolvers instead of the configured upstream pools:

### Use Cases

- **Active Directory**: route `corp.internal` → `10.0.0.10:53` (AD DNS)
- **Home lab**: route `home.lab` → `192.168.1.1:53` (local resolver)
- **Split-horizon**: route `internal.company.com` → internal DNS while everything else uses DoH

### Configuration

Managed via dashboard: **Clients > Groups > [Group] > Forwarding**

Or via the REST API:
```json
{
  "domain": "corp.internal",
  "upstream": "10.0.0.10:53",
  "group_id": 1
}
```

---

## Default Group

All clients that are not explicitly assigned to a group use the **Default** group. The default group uses the global blocking settings from `ferrous-dns.toml`.

---

## Client Dashboard

The Clients section of the dashboard shows:

- **Active clients** — last seen within 24 hours
- **Query count** per client (24h / 7d)
- **Block rate** per client
- **Top queried domains** per client
- **Group membership**
- **Last seen** timestamp and hostname

---

## PROXY Protocol v2

When Ferrous DNS runs behind a load balancer (HAProxy, nginx, AWS NLB), the real client IP is hidden. Enable PROXY Protocol v2 to restore accurate client detection:

```toml
[server]
proxy_protocol_enabled = true
```

See [Security](security.md#proxy-protocol) for details.
