# DNS64

DNS64 (RFC 6147) lets **IPv6-only clients** reach **IPv4-only services** by
synthesizing `AAAA` records from `A` records. Ferrous DNS implements the DNS64
half; the matching packet translation is handled by a separate **NAT64 gateway**
on your network.

## What it is

Many networks are now IPv6-only, but much of the internet still answers only on
IPv4. When an IPv6-only client asks for `AAAA example.com` and the name has only
an `A` record, the lookup returns nothing usable and the connection fails.

DNS64 fixes this on the resolver side: it re-queries the `A` record and returns a
synthetic `AAAA` that embeds the IPv4 address inside a NAT64 prefix. The client
connects to that IPv6 address, and the NAT64 gateway translates the traffic back
to IPv4.

!!! warning "A NAT64 gateway is required"
    DNS64 alone does nothing useful. The synthetic `AAAA` addresses are only
    reachable if a NAT64 gateway on your network routes the configured prefix.
    Enabling DNS64 without a NAT64 gateway **breaks** IPv6-only clients.

## How it works

```
Client (IPv6-only)            Ferrous DNS (DNS64)            Upstream
   |  AAAA example.com  ───────────►  |                         |
   |                                  |  AAAA example.com  ────► |
   |                                  |  ◄──── NODATA (no AAAA)  |
   |                                  |  A example.com     ────► |
   |                                  |  ◄──── 93.184.216.34     |
   |  ◄── AAAA 64:ff9b::5db8:d822 ──  |  (synthesized)          |
```

- Synthesis happens only on **NODATA** (the name exists with `A` records but no
  `AAAA`), never on NXDOMAIN.
- IPv4 addresses in **private/special ranges** (RFC 1918, loopback, link-local)
  are skipped — IPv6-only clients are not pointed at the NAT64 gateway for LAN
  addresses.
- Synthetic `AAAA` answers are **unsigned**: the DNSSEC `AD` bit is never set on
  them, and synthesis is skipped when the underlying `A` record is DNSSEC-Bogus.
- **Reverse PTR** queries for an address inside the NAT64 prefix are answered
  from the embedded IPv4's `in-addr.arpa` PTR.

## How to use

```toml title="ferrous-dns.toml"
[dns64]
enabled = true            # off by default
prefix  = "64:ff9b::/96"  # only /96 is supported (RFC 6052 well-known prefix)
```

Or from the Web UI: **Settings → DNS → DNS64**, toggle *Enable DNS64* and set the
prefix. DNS settings take effect after a restart.

## Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable DNS64 AAAA synthesis. |
| `prefix` | `string` | `"64:ff9b::/96"` | NAT64 prefix. Only `/96` is accepted; a malformed or non-/96 value disables DNS64 with a warning (fail-soft). |

## Observability

- Each synthesized AAAA answer is tagged `dns64_synthesized` in the query log
  (filterable via the `dns64` query parameter on the queries API).
- The `/metrics` endpoint exposes `ferrousdns_dns64_synthesized` — synthesized
  answers in the last 24h. (The Prometheus registry prefix is `ferrousdns`, so the
  metric name has a single underscore after it.)
