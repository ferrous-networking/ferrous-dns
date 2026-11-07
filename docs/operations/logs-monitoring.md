# Logs & Monitoring

## Logs

The server writes plain-text lines to standard output, one per event:

```text
2026-11-04T15:34:08.122201Z  INFO ferrous_dns::server::dns: DNS server ready — 16 workers on 0.0.0.0:53
```

There are no colour codes unless the output is a terminal, so the journal and `docker logs` store clean lines. The server keeps no log file of its own and has no JSON output: journald or the Docker log driver keep the lines, and ship them on if you need them elsewhere.

The level is `[logging] level` in the config (`error`, `warn`, `info`, `debug` or `trace`), or `--log-level` on the command line, or `FERROUS_LOG_LEVEL` in Docker. It is read at startup, so a change takes a restart. `info` is right for production. `debug` and `trace` produce a large volume under load, so use them only while troubleshooting.

=== "systemd"

    The journal collects the output:

    ```bash
    journalctl -u ferrous-dns -f               # follow
    journalctl -u ferrous-dns -b | grep -E " (WARN|ERROR) "
    ```

    journald rotates by its own limits. Set `SystemMaxUse=` in `/etc/systemd/journald.conf` to cap the space it takes. Every line reaches the journal at the same priority, so filter on the level word in the line rather than with `journalctl -p`.

=== "Docker"

    ```bash
    docker logs --since 1h ferrous-dns 2>&1 | grep -E " (WARN|ERROR) "
    ```

    Docker's default `json-file` driver keeps every line forever. Cap it in the compose file, as the bundled [`docker-compose.yml`](https://github.com/ferrous-networking/ferrous-dns/blob/main/docker-compose.yml) does:

    ```yaml
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    ```

Lines worth a look, all logged at `WARN`:

| Message | Meaning |
|:--------|:--------|
| `Invalid config value` | A value in the config was replaced at load. The line names the key, the value and what is used instead. See [Upgrading](../getting-started/installation.md#upgrading). |
| `Config key not read, its value is ignored` | A key from an older release that has been removed. The next save from the dashboard drops it. |
| `TLS cert file not found — DoT disabled` | A listener that needs a certificate did not start. The same line names DoQ and Web HTTPS. |
| `Server marked UNHEALTHY` | An upstream failed its health checks. |
| `Failed to fetch blocklist source; keeping the previous download` | A list could not be downloaded, and the last copy stays in force. |
| `UDP fallback capacity exhausted; queries dropped`, `Upstream query capacity exhausted; queries shed` | The server ran out of slots for queries waiting on an upstream. Clients were not answered, or got SERVFAIL. |
| `Query log channel full; entries dropped` | The database could not keep up with the query log. The queries were still answered. |

---

## Health check

`GET /ferrous/api/v1/health` needs no authentication. It answers `200` with `{"status":"ok","version":"…"}` while the DNS listener is up, and `503` when it is not. It does not test upstreams or the database: use it to tell a load balancer or an uptime monitor whether the process is serving, and use the alerts below for the rest. `/metrics` exports the same flag as `ferrousdns_dns_listening`.

`ferrous-dns --healthcheck` calls it with the same config and exits `0` or `1`. The Docker image's `HEALTHCHECK` runs it, and so can any script:

```bash
sudo -u ferrous-dns /usr/local/bin/ferrous-dns --config /etc/ferrous-dns/config.toml --healthcheck
```

---

## Metrics

Turn the Prometheus endpoint on in the config, and restart:

```toml
[server]
metrics_enabled = true
```

`/metrics` is served on the web port with no authentication, so anyone who reaches the port can read query volumes and the upstream list. Keep the port on a network your Prometheus is on, or block it on the [reverse proxy](tls-reverse-proxy.md). With the [firewall rule](tls-reverse-proxy.md#4-keep-the-dashboard-port-off-the-network) in place, let the Prometheus host through it. The full list of series is in [Metrics & Monitoring](../features/metrics.md).

A scrape job for a server with web TLS on, checking its self-signed certificate against a copy of it:

```yaml
scrape_configs:
  - job_name: ferrous-dns
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/ferrous-dns-upstream.pem   # a copy of [server.web_tls] tls_cert_path
      server_name: localhost
    static_configs:
      - targets: ["dns1.lan:8080", "dns2.lan:8080"]
```

Without web TLS, leave out `scheme` and `tls_config`. The generated certificate expires after a year: when you replace it, refresh this copy too, or the scrape fails. `FerrousDnsCertificateExpiring` below warns 21 days ahead.

### Alert rules

[`contrib/prometheus/ferrous-dns-alerts.yml`](https://github.com/ferrous-networking/ferrous-dns/blob/main/contrib/prometheus/ferrous-dns-alerts.yml) is a ready rule file. Load it from `prometheus.yml`, and check it with `promtool`:

```yaml
rule_files:
  - /etc/prometheus/rules/ferrous-dns-alerts.yml
```

```bash
promtool check rules ferrous-dns-alerts.yml
promtool test rules ferrous-dns-alerts.test.yml   # the unit tests beside it in contrib/
```

| Alert | Fires when | Look at |
|:------|:-----------|:--------|
| `FerrousDnsDown` | Prometheus cannot scrape the server for 2 minutes | The process, the host, the network path |
| `FerrousDnsListenerDown` | The DNS listener has not been serving for 2 minutes, while the web server still answers | The port taken by another process, or a bind address the host no longer has. The first log lines after the start say which |
| `FerrousDnsCertificateExpiring` | A certificate the web, DoT or DoQ listener serves expires within 21 days, or has expired, for 1 hour | [Renew it](tls-reverse-proxy.md#renewing-certificates) and restart: the server reads certificates only at start. Refresh every copy of the web one, the proxy's and Prometheus's `ca_file` |
| `FerrousDnsUpstreamDown` | One upstream server has failed its health checks for 5 minutes | The upstream itself and its pool in **Settings**. Other servers in the pool carry the load |
| `FerrousDnsPoolDown` | Every server of a pool has been down for 1 minute | Clients get SERVFAIL for everything that pool answers. Check the uplink |
| `FerrousDnsServfailRatioHigh` | More than 5% of replies are SERVFAIL for 10 minutes | Upstreams timing out, DNSSEC failures in `strict` mode, a conditional pool down. The Query Log shows which names |
| `FerrousDnsRefusedRatioHigh` | More than 5% of replies are REFUSED for 15 minutes | The rate limiter, strict DNS cookies, or `block_mode = "refused"`. `ferrousdns_queries_rate_limited` and the Query Log tell them apart |
| `FerrousDnsCacheHitRatioLow` | The cache answers less than 30% of lookups for 30 minutes | A cache too small for the traffic, or traffic of mostly unique names |
| `FerrousDnsShedding` | Any query was shed in the last 5 minutes | Upstreams too slow, or more traffic than the server takes |
| `FerrousDnsQueryLogDropping` | Any query log entry was dropped in the last 5 minutes | Disk speed, or `[database] query_log_channel_capacity` |
| `FerrousDnsDiskFull` | The data filesystem fills up within a day at the current rate | [Sizing](sizing.md#query-log-on-disk): retention and sampling. Needs node_exporter, and the right `mountpoint` in the rule |

The ratio alerts use the since-start counters (`ferrousdns_responses_total`, `ferrousdns_cache_*_total`), and they stay quiet below one reply a second, where a ratio is noise. Do not alert on `delta()` of the 24-hour gauges such as `ferrousdns_queries_rate_limited`. A rolling 24-hour count minus itself 15 minutes earlier compares the last 15 minutes with the same 15 minutes yesterday, not with zero.

```yaml
--8<-- "contrib/prometheus/ferrous-dns-alerts.yml"
```

These rules passed their `promtool` tests. The original set was also run against a live server: with 50 queries a second of cache misses and the only upstream stopped, `FerrousDnsPoolDown` fired after its minute, and `FerrousDnsServfailRatioHigh`, `FerrousDnsUpstreamDown` and `FerrousDnsCacheHitRatioLow` were pending, waiting out their own windows. For `FerrousDnsListenerDown` and `FerrousDnsCertificateExpiring`, the series they read were checked against a live server.
