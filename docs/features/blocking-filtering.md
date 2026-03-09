# Blocking & Filtering

Ferrous DNS provides multi-layer DNS filtering with support for blocklists, wildcards, regex, CNAME cloaking detection, and safe search enforcement.

---

## How Blocking Works

When a DNS query arrives, Ferrous DNS checks it through several filtering layers before forwarding to an upstream:

```text
Query: ads.doubleclick.net
         │
         ▼
  1. Allowlist check ──► in allowlist? → ALLOW (skip all blocking)
         │ no
         ▼
  2. Quick pre-check ──────► definitely not blocked? → skip lookup
         │ possible match
         ▼
  3. Exact domain match ─► in blocklist? → BLOCK (NXDOMAIN)
         │ no
         ▼
  4. Wildcard match ────► matches *.ads.com? → BLOCK
         │ no
         ▼
  5. Regex match ───────► matches pattern? → BLOCK
         │ no
         ▼
  6. Upstream resolution
         │
         ▼
  7. CNAME cloaking ────► CNAME points to blocked domain? → BLOCK
         │ clean
         ▼
     Return response
```

---

## Blocklists

### Adding Blocklists

Via dashboard: **Blocklists > Add Blocklist**

Via TOML (simple domains):
```toml
[blocking]
custom_blocked = [
    "ads.example.com",
    "tracker.badsite.org",
]
```

### Supported Formats

**Hosts file** (`0.0.0.0` or `127.0.0.1` format):
```text
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.org
127.0.0.1 malware.example.net
```

**Domain list** (one domain per line):
```text
ads.example.com
tracker.example.org
malware.example.net
```

**Wildcard** (blocks entire subdomain trees):
```text
*.ads.example.com
*.doubleclick.net
```

**Regex** (for complex patterns):
```text
/^ads\d+\.example\.com$/
/^tracking\./
/telemetry/
```

### Recommended Blocklists

| Name | URL | Size | Focus |
|:-----|:----|:-----|:------|
| Steven Black Unified | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | ~120k | Ads + Malware |
| OISD (small) | `https://small.oisd.nl/domainswild` | ~50k | Balanced |
| OISD (big) | `https://big.oisd.nl/domainswild` | ~200k | Comprehensive |
| HaGeZi Pro | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt` | ~500k | Comprehensive |
| HaGeZi Threat | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt` | ~1M | Security |
| EasyList | `https://easylist.to/easylist/easylist.txt` | ~80k | Ads |

---

## Allowlist

Domains in the allowlist bypass all blocking, even if present in a blocklist:

```toml
[blocking]
whitelist = [
    "safe.example.com",
    "cdn.trusted.net",
    "updates.software.com",
]
```

Or add directly from the query log dashboard with one click.

---

## CNAME Cloaking Detection

Some trackers hide behind first-party CNAME records to bypass simple domain blocklists:

```text
tracking.yoursite.com  CNAME  tracking.third-party-analytics.com
```

Without CNAME inspection, blocking `tracking.third-party-analytics.com` would be ineffective because the query is for `tracking.yoursite.com`.

Ferrous DNS resolves the full CNAME chain and blocks the response if **any** CNAME in the chain points to a blocked domain. This is enabled automatically when blocking is active.

---

## Safe Search Enforcement

Force safe search modes on search engines and video platforms to prevent explicit content:

Managed via dashboard: **Settings > Safe Search**

| Platform | Enforcement Method |
|:---------|:------------------|
| Google | DNS redirect to `forcesafesearch.google.com` |
| Bing | DNS redirect to `strict.bing.com` |
| YouTube | DNS redirect to `restrictmoderate.youtube.com` |
| DuckDuckGo | DNS redirect to safe search endpoint |

Safe Search can be enabled globally or per client group (e.g. only on the "Kids" group).

---

## Blockable Services (1-Click)

Pre-defined service categories that can be blocked network-wide or per group:

**Advertising**
- Google Ads, DoubleClick, Facebook Ads, Amazon Ads

**Analytics & Tracking**
- Google Analytics, Mixpanel, Hotjar, Segment, Amplitude

**Social Media**
- Facebook/Instagram, TikTok, Twitter/X, Snapchat, Pinterest

**Telemetry**
- Microsoft telemetry, Apple telemetry, Windows Update telemetry

**Adult Content**
- Adult content domains

**Gambling**
- Online gambling domains

Access via dashboard: **Services**

See [Block Services & Schedules](block-services.md) for the full guide with per-group examples, custom services, and time-based scheduling.

---

## Per-Group Blocking

Different blocking policies per client group allow fine-grained control:

- **Kids devices**: strict blocklist + safe search + social media blocked
- **Work devices**: ad blocking + tracking blocked, social media allowed
- **IoT devices**: block everything except required cloud endpoints
- **Guest network**: basic ad blocking only

See [Client Management](client-management.md) for group setup.

---

## Query Log Actions

Every query in the query log has quick-action buttons:

- **Block**: adds the domain to the global blocklist
- **Allow**: adds the domain to the allowlist

Changes take effect immediately without a restart.

---

## Blocking Response

When a query is blocked, Ferrous DNS returns:

- `NXDOMAIN` — domain does not exist (standard behavior, compatible with all clients)

Some deployments prefer returning `0.0.0.0` (A record) to prevent connection timeouts. This can be configured in the dashboard under **Settings > Blocking Response**.
