# Blocking Configuration

The `[blocking]` section controls the base blocking settings. Blocklists, client groups, and per-group policies are managed via the dashboard or REST API.

---

## Basic Options

```toml
[blocking]
enabled = true
custom_blocked = []
whitelist = []
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `true` | Enable DNS-based blocking globally |
| `custom_blocked` | `[]` | Additional domains to block beyond downloaded blocklists |
| `whitelist` | `[]` | Domains to always allow, even if present in a blocklist |

### Example

```toml
[blocking]
enabled = true
custom_blocked = [
    "ads.example.com",
    "tracker.example.org",
]
whitelist = [
    "safe.example.com",
    "cdn.trusted.net",
]
```

---

## Blocklist Management (Dashboard)

All blocklist management is done via the dashboard or REST API — not the TOML file.

### Adding a Blocklist

1. Go to **Blocklists** in the sidebar
2. Click **Add Blocklist**
3. Enter a name and URL
4. Select the format (hosts, domains, or regex)
5. Click **Save**, then **Sync**

### Supported Formats

| Format | Example |
|:-------|:--------|
| Hosts file | `0.0.0.0 ads.example.com` |
| Domain list | `ads.example.com` |
| Wildcard | `*.ads.example.com` |
| Regex | `/^ads\d+\.example\.com$/` |

### Blocklist URL Examples

```text title="Blocklist URLs"
# Hosts format
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Domain list
https://small.oisd.nl/domainswild

# Regex-capable
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt
```

---

## Wildcard Blocking

Ferrous DNS supports wildcard patterns for blocking entire subdomains:

```text
*.ads.example.com    — blocks ads.example.com, video.ads.example.com, etc.
*.doubleclick.net    — blocks all subdomains of doubleclick.net
```

Wildcards can be added in the dashboard under **Blocklists > Custom Rules**.

---

## Regex Support

Regex patterns are supported in blocklists and custom rules:

```text
/^ads\d+\.example\.com$/     — matches ads1.example.com, ads42.example.com
/tracker/                    — matches any domain containing "tracker"
```

---

## CNAME Cloaking Detection

Ferrous DNS inspects CNAME chains in responses. If a CNAME points to a blocked domain, the entire response is blocked — even if the queried domain is not on the blocklist.

This catches trackers that hide behind first-party CNAMEs (e.g. `tracking.yoursite.com CNAME tracking.thirdparty.com`).

CNAME cloaking detection is enabled automatically when blocking is active.

---

## Safe Search Enforcement

Force safe search for major search engines and video platforms:

Managed in the dashboard under **Services > Safe Search**.

| Platform | What it does |
|:---------|:-------------|
| Google | Redirects to `forcesafesearch.google.com` |
| Bing | Redirects to `strict.bing.com` |
| YouTube | Restricts to `restrictmoderate.youtube.com` |
| DuckDuckGo | Forces safe search mode |

---

## Blockable Services (1-Click)

Pre-defined service categories can be blocked with a single click from the dashboard under **Services**:

- Social Media (Facebook, Instagram, TikTok, Twitter/X)
- Advertising networks
- Telemetry & tracking (Microsoft, Apple, Google)
- Adult content
- Gambling
- Gaming platforms

These use curated domain lists maintained by the Ferrous DNS project.

---

## Per-Client Group Policies

Different blocking rules can be applied to different client groups:

1. Create client groups in **Clients > Groups**
2. Assign blocklists to each group
3. Set schedules for time-based blocking (e.g. block social media on school devices during school hours)

See [Client Management](../features/client-management.md) for details.

---

## Allow/Block from Query Log

Any domain in the query log can be instantly added to the allowlist or blocklist by clicking the Allow or Block button next to it. Changes take effect immediately without a server restart.
